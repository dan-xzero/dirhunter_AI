from __future__ import annotations

import asyncio
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arq import create_pool
from arq.connections import RedisSettings
from sqlalchemy import func, select

from app.db import SessionLocal
from app.models import Finding, Scan
from app.services.findings import complete_scan, create_scan, update_scan_state
from app.settings import settings


def build_scan_command(scan_id: int, domains: str | None = None, wordlist: str | None = None, args: list[str] | None = None) -> list[str]:
    command = [sys.executable, "main_optimized.py"]
    if domains:
        command.extend(["--domains", domains])
    if wordlist:
        command.extend(["--wordlist", wordlist])
    command.extend(args or [])
    return command


async def enqueue_scan(domains: str | None = None, wordlist: str | None = None, args: list[str] | None = None) -> int:
    scan_id = await create_scan(trigger="api", wordlist=wordlist, args={"domains": domains, "args": args or []})
    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    await redis.enqueue_job("run_scan", scan_id, domains, wordlist, args or [])
    return scan_id


async def enqueue_scan_resume(scan_id: int, *, reason: str = "manual") -> bool:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return False
        payload = scan.args or {}
        domains = payload.get("domains")
        args = list(payload.get("args") or [])
        wordlist = scan.wordlist
        stats = dict(scan.stats or {})
        for key in ("exit_code", "error"):
            stats.pop(key, None)
        attempts = int(stats.get("resume_attempts") or 0) + 1
        stats.update(
            {
                "resume_attempts": attempts,
                "resume_reason": reason,
                "resume_requested_at": _utcnow_iso(),
            }
        )
        scan.status = "running"
        scan.finished_at = None
        scan.stats = stats
        await session.commit()

    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    await redis.enqueue_job("run_scan", scan_id, domains, wordlist, args)
    return True


async def run_scan(ctx: dict[str, Any], scan_id: int, domains: str | None, wordlist: str | None, args: list[str]) -> None:
    domain_items = _split_domains(domains)
    if len(domain_items) > 1:
        await _enqueue_domain_jobs(scan_id, domain_items, wordlist, args)
        return
    if len(domain_items) == 1:
        await run_scan_domain(ctx, scan_id, domain_items[0], wordlist, args)
        return

    code, pid = await _run_scan_process(scan_id, domains, wordlist, args, partial=False)
    if code != 0:
        await complete_scan(scan_id, status="failed", stats={"exit_code": code, "pid": pid})
        raise RuntimeError(f"scan {scan_id} failed with exit code {code}")

    await _send_slack_digest_if_enabled(scan_id)


async def run_scan_domain(
    ctx: dict[str, Any],
    scan_id: int,
    domain: str,
    wordlist: str | None,
    args: list[str],
) -> None:
    await _mark_domain(scan_id, domain, "running")
    try:
        code, pid = await _run_scan_process(scan_id, domain, wordlist, args, partial=True)
    except asyncio.CancelledError:
        final_status = await _mark_domain(scan_id, domain, "failed", error="worker_timeout")
        if final_status:
            await _send_slack_digest_if_enabled(scan_id)
        raise

    if code != 0:
        final_status = await _mark_domain(scan_id, domain, "failed", error=f"exit_code:{code}", pid=pid)
        if final_status:
            await _send_slack_digest_if_enabled(scan_id)
        raise RuntimeError(f"scan {scan_id} domain {domain} failed with exit code {code}")

    final_status = await _mark_domain(scan_id, domain, "completed", pid=pid)
    if final_status == "completed":
        await _send_slack_digest_if_enabled(scan_id)


async def _run_scan_process(
    scan_id: int,
    domains: str | None,
    wordlist: str | None,
    args: list[str],
    *,
    partial: bool,
) -> tuple[int, int | None]:
    env = os.environ.copy()
    env["USE_PG"] = "1"
    env["SCAN_ID"] = str(scan_id)
    env.setdefault("USE_LEGACY_HTML", "1")
    if partial:
        env["DIRHUNTER_PARTIAL_SCAN"] = "1"

    command = build_scan_command(scan_id, domains, wordlist, args)
    await update_scan_state(
        scan_id,
        status="running",
        clear_finished_at=True,
        stats={
            "worker_started_at": _utcnow_iso(),
            "last_log_at": _utcnow_iso(),
            "command": " ".join(command),
            "active_domain": domains,
        },
    )
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=Path.cwd(),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    await update_scan_state(scan_id, stats={"pid": process.pid})
    assert process.stdout is not None
    last_heartbeat = 0.0
    try:
        async for line in process.stdout:
            print(line.decode(errors="replace").rstrip())
            now = time.monotonic()
            if now - last_heartbeat >= 10:
                await update_scan_state(scan_id, stats={"last_log_at": _utcnow_iso(), "pid": process.pid})
                last_heartbeat = now
        code = await process.wait()
    except asyncio.CancelledError:
        await _terminate_process(process)
        raise

    return code, process.pid


async def _enqueue_domain_jobs(scan_id: int, domains: list[str], wordlist: str | None, args: list[str]) -> None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return
        stats = dict(scan.stats or {})
        domain_status = dict(stats.get("domain_status") or {})
        pending = [domain for domain in domains if domain_status.get(domain) != "completed"]
        stats.update(
            {
                "domains_total": len(domains),
                "domains_queued": len(pending),
                "domain_status": {domain: domain_status.get(domain, "queued") for domain in domains},
                "last_log_at": _utcnow_iso(),
            }
        )
        scan.status = "running"
        scan.finished_at = None
        scan.stats = stats
        await session.commit()

    if not pending:
        await _mark_scan_if_finished(scan_id)
        return

    redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    for domain in pending:
        await redis.enqueue_job("run_scan_domain", scan_id, domain, wordlist, args)


async def _mark_domain(
    scan_id: int,
    domain: str,
    status: str,
    *,
    error: str | None = None,
    pid: int | None = None,
) -> str | None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return None

        stats = dict(scan.stats or {})
        domain_status = dict(stats.get("domain_status") or {})
        domain_errors = dict(stats.get("domain_errors") or {})
        domain_attempts = dict(stats.get("domain_attempts") or {})
        if status == "running":
            domain_attempts[domain] = int(domain_attempts.get(domain) or 0) + 1

        domain_status[domain] = status
        if error:
            domain_errors[domain] = error

        total_domains = int(stats.get("domains_total") or len(domain_status) or 1)
        completed = sum(1 for value in domain_status.values() if value == "completed")
        failed = sum(1 for value in domain_status.values() if value == "failed")
        running_domains = [name for name, value in domain_status.items() if value == "running"]
        counts = await _scan_counts(session, scan_id)

        stats.update(
            {
                **counts,
                "domains": total_domains,
                "domains_total": total_domains,
                "domains_completed": completed,
                "domains_failed": failed,
                "domains_running": len(running_domains),
                "domain_status": domain_status,
                "domain_errors": domain_errors,
                "domain_attempts": domain_attempts,
                "active_domain": domain if status == "running" else (running_domains[0] if running_domains else None),
                "active_domains": running_domains,
                "last_domain": domain,
                "last_log_at": _utcnow_iso(),
            }
        )
        if pid:
            stats["pid"] = pid

        final_status: str | None = None
        if completed + failed >= total_domains:
            final_status = "failed" if failed else "completed"
            scan.status = final_status
            scan.finished_at = datetime.now(timezone.utc)
            if failed:
                stats["error"] = "domain_failures"
            else:
                stats.pop("error", None)
        else:
            scan.status = "running"
            scan.finished_at = None

        scan.stats = stats
        await session.commit()
        return final_status


async def _mark_scan_if_finished(scan_id: int) -> str | None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return None
        stats = dict(scan.stats or {})
        domain_status = dict(stats.get("domain_status") or {})
        total_domains = int(stats.get("domains_total") or len(domain_status) or 0)
        completed = sum(1 for value in domain_status.values() if value == "completed")
        failed = sum(1 for value in domain_status.values() if value == "failed")
        if total_domains and completed + failed >= total_domains:
            final_status = "failed" if failed else "completed"
            scan.status = final_status
            scan.finished_at = datetime.now(timezone.utc)
            scan.stats = {**stats, **(await _scan_counts(session, scan_id))}
            await session.commit()
            return final_status
        return None


async def _scan_counts(session, scan_id: int) -> dict[str, Any]:
    total = await session.scalar(select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id))
    by_status = await session.execute(
        select(Finding.finding_status, func.count())
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.finding_status)
    )
    status_counts = {status or "unknown": count for status, count in by_status.all()}
    return {
        "findings": int(total or 0),
        "new": int(status_counts.get("new") or 0),
        "changed": int(status_counts.get("changed") or 0),
        "recurring": int(status_counts.get("recurring") or status_counts.get("existing") or 0),
    }


async def _send_slack_digest_if_enabled(scan_id: int) -> None:
    if os.environ.get("WEBHOOK_URL") and os.environ.get("USE_NEW_SLACK", "").lower() in {"1", "true", "yes", "on"}:
        try:
            from app.services.slack import send_digest

            sent = await send_digest(scan_id, os.environ.get("WEBHOOK_URL"))
            print("Slack digest sent successfully" if sent else "Slack digest failed")
        except Exception as exc:
            print(f"Slack digest failed with exception: {exc}")


def _split_domains(domains: str | None) -> list[str]:
    if not domains:
        return []
    if "," in domains:
        return [domain.strip() for domain in domains.split(",") if domain.strip()]
    path = Path(domains)
    if len(domains) < 240 and path.exists() and path.is_file():
        return [line.strip() for line in path.read_text(errors="ignore").splitlines() if line.strip() and not line.startswith("#")]
    return [domain.strip() for domain in domains.split(",") if domain.strip()]


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _terminate_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        process.send_signal(signal.SIGTERM)
        await asyncio.wait_for(process.wait(), timeout=10)
    except Exception:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except Exception:
            pass


class WorkerSettings:
    functions = [run_scan, run_scan_domain]
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    job_timeout = 1800
    max_jobs = int(os.getenv("DIRHUNTER_WORKER_MAX_JOBS", "2"))

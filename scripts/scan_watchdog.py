#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import SessionLocal
from app.models import Scan
from app.services.scan_runner import enqueue_scan_resume


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resume failed or abandoned DirHunter scans.")
    parser.add_argument("--interval", type=int, default=int(os.getenv("SCAN_WATCHDOG_INTERVAL", "300")))
    parser.add_argument("--stale-minutes", type=int, default=int(os.getenv("SCAN_WATCHDOG_STALE_MINUTES", "45")))
    parser.add_argument("--max-attempts", type=int, default=int(os.getenv("SCAN_WATCHDOG_MAX_ATTEMPTS", "3")))
    parser.add_argument("--once", action="store_true", help="Run one check and exit.")
    return parser.parse_args()


async def find_resume_candidates(stale_minutes: int, max_attempts: int) -> list[tuple[int, str, int | None]]:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=stale_minutes)
    candidates: list[tuple[int, str, int | None]] = []
    async with SessionLocal() as session:
        result = await session.execute(
            select(Scan).where(Scan.status.in_(["failed", "running"])).order_by(Scan.started_at.desc()).limit(100)
        )
        for scan in result.scalars():
            stats = scan.stats or {}
            if stats.get("resume_disabled"):
                continue
            attempts = int(stats.get("resume_attempts") or 0)
            if attempts >= max_attempts:
                continue
            pid = _as_pid(stats.get("pid"))
            if scan.status == "failed":
                candidates.append((scan.id, "failed", pid))
                continue
            if scan.status == "running" and scan.started_at and scan.started_at < cutoff:
                if not _pid_alive(pid):
                    candidates.append((scan.id, "stale_running_dead_pid", pid))
                    continue
                if _has_stale_running_domains(stats, cutoff):
                    candidates.append((scan.id, "stale_running_domains", pid))
    return candidates


async def resume_once(stale_minutes: int, max_attempts: int) -> int:
    resumed = 0
    for scan_id, reason, pid in await find_resume_candidates(stale_minutes, max_attempts):
        if reason.startswith("stale") and pid:
            killed = _terminate_pid_tree(pid)
            if killed:
                print(f"terminated stale scan process tree pid={pid} children={killed}", flush=True)
        if await enqueue_scan_resume(scan_id, reason=reason):
            print(f"resumed scan {scan_id} reason={reason}", flush=True)
            resumed += 1
    if resumed == 0:
        print("no scans needed resume", flush=True)
    return resumed


def _pid_alive(pid: object) -> bool:
    value = _as_pid(pid)
    if value is None:
        return False
    try:
        os.kill(value, 0)
        return True
    except OSError:
        return False


def _as_pid(pid: object) -> int | None:
    try:
        return int(pid)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _has_stale_running_domains(stats: dict, cutoff: datetime) -> bool:
    domain_status = stats.get("domain_status") or {}
    running_count = sum(1 for status in domain_status.values() if status == "running")
    if running_count == 0:
        return False
    heartbeat = _parse_dt(stats.get("last_log_at")) or _parse_dt(stats.get("worker_started_at"))
    return heartbeat is not None and heartbeat < cutoff


def _parse_dt(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _terminate_pid_tree(pid: int) -> list[int]:
    pids = _pid_tree(pid)
    if not pids:
        return []
    for sig, delay in ((signal.SIGTERM, 5), (signal.SIGKILL, 1)):
        for value in reversed(pids):
            try:
                os.kill(value, sig)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass
        time.sleep(delay)
        if not any(_pid_alive(value) for value in pids):
            break
    return pids


def _pid_tree(root: int) -> list[int]:
    if not _pid_alive(root):
        return []
    children: dict[int, list[int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text(errors="ignore")
        except OSError:
            continue
        ppid = None
        for line in status.splitlines():
            if line.startswith("PPid:"):
                try:
                    ppid = int(line.split()[1])
                except (IndexError, ValueError):
                    ppid = None
                break
        if ppid is not None:
            children.setdefault(ppid, []).append(int(entry.name))
    output: list[int] = []
    pending = [root]
    while pending:
        current = pending.pop()
        output.append(current)
        pending.extend(children.get(current, []))
    return output


async def main() -> None:
    args = parse_args()
    stop = asyncio.Event()

    def _stop(*_: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while not stop.is_set():
        await resume_once(args.stale_minutes, args.max_attempts)
        if args.once:
            return
        try:
            await asyncio.wait_for(stop.wait(), timeout=args.interval)
        except asyncio.TimeoutError:
            pass


if __name__ == "__main__":
    asyncio.run(main())

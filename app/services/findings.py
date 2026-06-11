from __future__ import annotations

import asyncio
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Select, delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db import SessionLocal, engine
from app.models import (
    AuditLog,
    CVE,
    Domain,
    EndpointHash,
    Finding,
    FindingTriage,
    FindingValidation,
    Scan,
    Secret,
    TechDetection,
)
from app.services.serialization import body_excerpt_from_finding, clean_text, json_safe
from utils.ai_analyzer import get_category_priority

logger = logging.getLogger(__name__)


def _run_sync(coro):
    async def _run_with_fresh_pool():
        # Scanner subprocesses can inherit async engine state from a parent loop.
        # Drop inherited pool connections before/after sync wrappers to avoid
        # "Future attached to a different loop" during partial persistence.
        await engine.dispose(close=False)
        try:
            return await coro
        finally:
            await engine.dispose()

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_run_with_fresh_pool())
    raise RuntimeError("Synchronous wrapper cannot run inside an active event loop")


async def create_scan(
    trigger: str = "manual",
    wordlist: str | None = None,
    args: dict[str, Any] | None = None,
    status: str = "running",
) -> int:
    async with SessionLocal() as session:
        scan = Scan(trigger=trigger, wordlist=wordlist, args=json_safe(args or {}), stats={}, status=status)
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        return scan.id


def create_scan_sync(**kwargs) -> int:
    return _run_sync(create_scan(**kwargs))


async def complete_scan(scan_id: int, status: str = "completed", stats: dict[str, Any] | None = None) -> None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return
        scan.status = status
        scan.finished_at = datetime.now(timezone.utc)
        if stats is not None:
            scan.stats = {**(scan.stats or {}), **json_safe(stats)}
        await session.commit()


def complete_scan_sync(scan_id: int, **kwargs) -> None:
    return _run_sync(complete_scan(scan_id, **kwargs))


async def update_scan_state(
    scan_id: int,
    *,
    status: str | None = None,
    stats: dict[str, Any] | None = None,
    clear_finished_at: bool = False,
) -> None:
    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return
        if status is not None:
            scan.status = status
        if clear_finished_at:
            scan.finished_at = None
        if stats:
            scan.stats = {**(scan.stats or {}), **json_safe(stats)}
        await session.commit()


def update_scan_state_sync(scan_id: int, **kwargs) -> None:
    return _run_sync(update_scan_state(scan_id, **kwargs))


async def persist_and_complete_scan(
    scan_id: int,
    all_results: dict[str, list[dict[str, Any]]],
    *,
    status: str = "completed",
) -> dict[str, int]:
    stats = await persist_batch(scan_id, all_results)
    await complete_scan(scan_id, status=status, stats=stats)
    return stats


def persist_and_complete_scan_sync(
    scan_id: int,
    all_results: dict[str, list[dict[str, Any]]],
    *,
    status: str = "completed",
) -> dict[str, int]:
    return _run_sync(persist_and_complete_scan(scan_id, all_results, status=status))


async def persist_batch(scan_id: int | None, all_results: dict[str, list[dict[str, Any]]]) -> dict[str, int]:
    async with SessionLocal() as session:
        stats = Counter()
        for domain, findings in (all_results or {}).items():
            domain_row = await _upsert_domain(session, domain, _domain_env(domain))
            for item in findings or []:
                finding = await _upsert_finding(session, scan_id, domain_row.id, domain, item)
                stats["findings"] += 1
                await _replace_child_records(session, finding, item)

        if scan_id:
            scan = await session.get(Scan, scan_id)
            if scan:
                scan.stats = {
                    **(scan.stats or {}),
                    "domains": len(all_results or {}),
                    "findings": stats["findings"],
                    "new": sum(
                        1
                        for findings in (all_results or {}).values()
                        for item in findings
                        if item.get("finding_status") == "new"
                    ),
                    "changed": sum(
                        1
                        for findings in (all_results or {}).values()
                        for item in findings
                        if item.get("finding_status") == "changed"
                    ),
                }

        await session.commit()
        return dict(stats)


def persist_batch_sync(scan_id: int | None, all_results: dict[str, list[dict[str, Any]]]) -> dict[str, int]:
    return _run_sync(persist_batch(scan_id, all_results))


async def _upsert_domain(session: AsyncSession, host: str, env: str) -> Domain:
    stmt = (
        insert(Domain)
        .values(host=host, env=env, tags=[])
        .on_conflict_do_update(index_elements=[Domain.host], set_={"env": env})
        .returning(Domain.id)
    )
    domain_id = (await session.execute(stmt)).scalar_one()
    return (await session.get(Domain, domain_id))  # type: ignore[return-value]


def _domain_env(domain: str) -> str:
    try:
        with open("domains/prod_domains.txt", "r", encoding="utf-8") as handle:
            if domain in {line.strip() for line in handle if line.strip()}:
                return "prod"
    except OSError:
        pass
    return "nonprod"


async def _upsert_finding(
    session: AsyncSession,
    scan_id: int | None,
    domain_id: int,
    domain: str,
    item: dict[str, Any],
) -> Finding:
    url = clean_text(item.get("url") or "") or ""
    sha1_hash = clean_text(item.get("sha1_hash") or item.get("body_hash") or "") or ""
    now = datetime.now(timezone.utc)
    status_code = item.get("status") or item.get("final_status")
    content_length = item.get("length") or item.get("content_length")
    ai_tag = item.get("ai_tag") or "Other"
    values = {
        "scan_id": scan_id,
        "domain_id": domain_id,
        "url": url,
        "path": clean_text(item.get("path")),
        "status_code": status_code,
        "content_length": content_length,
        "sha1_hash": sha1_hash,
        "fuzzy_hash": clean_text(item.get("fuzzy_hash")),
        "ai_tag": clean_text(ai_tag) or "Other",
        "ai_priority": get_category_priority(ai_tag),
        "finding_status": item.get("finding_status") or "new",
        "first_seen": _parse_dt(item.get("first_seen")) or now,
        "last_seen": now,
        "times_seen": int(item.get("times_seen") or 1),
        "content_changed": item.get("finding_status") == "changed",
        "screenshot_path": clean_text(item.get("screenshot")),
        "headers": json_safe(item.get("headers") or {}),
        "body_excerpt": body_excerpt_from_finding(item),
        "download_meta": json_safe(item.get("download_meta") or {}),
        "raw": json_safe(item),
    }
    stmt = (
        insert(Finding)
        .values(**values)
        .on_conflict_do_update(
            constraint="uq_findings_url_sha1",
            set_={
                "scan_id": scan_id,
                "path": values["path"],
                "status_code": values["status_code"],
                "content_length": values["content_length"],
                "fuzzy_hash": values["fuzzy_hash"],
                "last_seen": now,
                "times_seen": Finding.times_seen + 1,
                "finding_status": values["finding_status"],
                "content_changed": values["content_changed"],
                "ai_tag": values["ai_tag"],
                "ai_priority": values["ai_priority"],
                "screenshot_path": values["screenshot_path"],
                "headers": values["headers"],
                "body_excerpt": values["body_excerpt"],
                "download_meta": values["download_meta"],
                "raw": values["raw"],
            },
        )
        .returning(Finding.id)
    )
    finding_id = (await session.execute(stmt)).scalar_one()

    await session.execute(
        insert(EndpointHash)
        .values(url=url, sha1=sha1_hash, last_seen=now)
        .on_conflict_do_update(index_elements=[EndpointHash.url], set_={"sha1": sha1_hash, "last_seen": now})
    )

    finding = await session.get(Finding, finding_id)
    if finding is None:
        raise RuntimeError(f"Unable to load persisted finding {finding_id}")
    return finding


async def _replace_child_records(session: AsyncSession, finding: Finding, item: dict[str, Any]) -> None:
    await session.execute(delete(Secret).where(Secret.finding_id == finding.id))
    existing_tech = (await session.execute(select(TechDetection.id).where(TechDetection.finding_id == finding.id))).scalars()
    tech_ids = list(existing_tech)
    if tech_ids:
        await session.execute(delete(CVE).where(CVE.tech_detection_id.in_(tech_ids)))
        await session.execute(delete(TechDetection).where(TechDetection.id.in_(tech_ids)))

    for secret in _extract_secrets(item):
        session.add(Secret(finding_id=finding.id, **secret))

    for tech in _extract_tech(item):
        tech_row = TechDetection(finding_id=finding.id, **tech["tech"])
        session.add(tech_row)
        await session.flush()
        for cve in tech["cves"]:
            session.add(CVE(tech_detection_id=tech_row.id, **cve))

    validation = item.get("llm_validation")
    if validation:
        await upsert_validation(session, finding.id, validation)


async def upsert_validation(session: AsyncSession, finding_id: int, validation: dict[str, Any]) -> None:
    stmt = (
        insert(FindingValidation)
        .values(
            finding_id=finding_id,
            llm_verdict=validation.get("verdict", "inconclusive"),
            llm_confidence=float(validation.get("confidence") or 0),
            llm_reasoning=validation.get("reason"),
            category_corrected=validation.get("category_corrected"),
            model=validation.get("model", "unknown"),
            tokens_used=int(validation.get("tokens_used") or 0),
            cost_usd=float(validation.get("cost_usd") or 0),
        )
        .on_conflict_do_update(
            constraint="uq_findings_validation_finding",
            set_={
                "llm_verdict": validation.get("verdict", "inconclusive"),
                "llm_confidence": float(validation.get("confidence") or 0),
                "llm_reasoning": validation.get("reason"),
                "category_corrected": validation.get("category_corrected"),
                "model": validation.get("model", "unknown"),
                "tokens_used": int(validation.get("tokens_used") or 0),
                "cost_usd": float(validation.get("cost_usd") or 0),
                "validated_at": datetime.now(timezone.utc),
            },
        )
    )
    await session.execute(stmt)


def _extract_secrets(item: dict[str, Any]) -> list[dict[str, Any]]:
    download_meta = item.get("download_meta") or {}
    secrets = []
    for secret in download_meta.get("th_secrets", []) or []:
        raw = secret.get("redacted") or secret.get("raw")
        reason = secret.get("reason")
        secrets.append(
            {
                "type": secret.get("type") or "unknown",
                "risk": secret.get("risk") or "medium",
                "snippet": raw,
                "reason": reason,
            }
        )
    return secrets


def _extract_tech(item: dict[str, Any]) -> list[dict[str, Any]]:
    tech_dict = item.get("tech") or {}
    cve_details = tech_dict.get("cve_details") or {}
    output = []
    for name, info in tech_dict.items():
        if name in {"cve_vulns", "cve_details", "name", "version", "wapp"} or not isinstance(info, dict):
            continue
        cves = []
        for cve_id in cve_details.get(name.lower(), []) or []:
            cves.append({"cve_id": str(cve_id), "severity": None})
        output.append(
            {
                "tech": {
                    "name": name,
                    "version": info.get("version"),
                    "source": info.get("source"),
                    "confidence": float(info.get("confidence") or 0),
                },
                "cves": cves,
            }
        )
    return output


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


async def list_findings(
    session: AsyncSession,
    *,
    scan_id: int | None = None,
    domain: str | None = None,
    status: str | None = None,
    tag: str | None = None,
    triage: str | None = None,
    verdict: str | None = None,
    include_likely_fp: bool = False,
    include_unvalidated: bool = False,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Finding], int]:
    stmt = _findings_query(
        scan_id=scan_id,
        domain=domain,
        status=status,
        tag=tag,
        triage=triage,
        verdict=verdict,
        include_likely_fp=include_likely_fp,
        include_unvalidated=include_unvalidated,
        q=q,
    )
    id_subquery = stmt.with_only_columns(Finding.id).order_by(None).subquery()
    count_stmt = select(func.count(func.distinct(id_subquery.c.id))).select_from(id_subquery)
    total = (await session.execute(count_stmt)).scalar_one()
    result = await session.execute(
        stmt.options(
            selectinload(Finding.domain),
            selectinload(Finding.validation),
            selectinload(Finding.triage_events),
            selectinload(Finding.secrets),
            selectinload(Finding.tech_detections).selectinload(TechDetection.cves),
        )
        .order_by(Finding.last_seen.desc(), Finding.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().unique()), total


def _findings_query(**filters) -> Select[tuple[Finding]]:
    stmt = select(Finding).join(Domain)
    latest_triage_label = (
        select(FindingTriage.label)
        .where(FindingTriage.finding_id == Finding.id)
        .order_by(FindingTriage.labeled_at.desc(), FindingTriage.id.desc())
        .limit(1)
        .correlate(Finding)
        .scalar_subquery()
    )
    if filters.get("scan_id"):
        stmt = stmt.where(Finding.scan_id == filters["scan_id"])
    if filters.get("domain"):
        stmt = stmt.where(Domain.host.ilike(f"%{filters['domain']}%"))
    if filters.get("status"):
        stmt = stmt.where(Finding.finding_status == filters["status"])
    if filters.get("tag"):
        stmt = stmt.where(Finding.ai_tag == filters["tag"])
    if filters.get("verdict"):
        stmt = stmt.join(FindingValidation, isouter=True).where(FindingValidation.llm_verdict == filters["verdict"])
    else:
        stmt = stmt.join(FindingValidation, isouter=True)
        if not filters.get("include_likely_fp"):
            stmt = stmt.where(or_(FindingValidation.id.is_(None), FindingValidation.llm_verdict != "likely_fp"))
        if not filters.get("include_unvalidated"):
            stmt = stmt.where(FindingValidation.id.is_not(None))
    if filters.get("triage"):
        stmt = stmt.where(latest_triage_label == filters["triage"])
    elif not filters.get("include_likely_fp"):
        stmt = stmt.where(or_(latest_triage_label.is_(None), latest_triage_label != "fp"))
    if filters.get("q"):
        q = f"%{filters['q']}%"
        stmt = stmt.where((Finding.url.ilike(q)) | (Finding.body_excerpt.ilike(q)) | (Domain.host.ilike(q)))
    return stmt


async def add_triage(finding_id: int, label: str, user: str = "system", note: str | None = None) -> FindingTriage:
    async with SessionLocal() as session:
        triage = FindingTriage(finding_id=finding_id, label=label, user=user, note=note)
        session.add(triage)
        session.add(
            AuditLog(
                actor=user,
                action="triage.create",
                target_type="finding",
                target_id=str(finding_id),
                details={"label": label, "note": note},
            )
        )
        await session.commit()
        await session.refresh(triage)
        return triage

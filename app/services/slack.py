from __future__ import annotations

import asyncio
import os
from typing import Any

import requests
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import SessionLocal, engine
from app.models import Finding, FindingValidation, Scan, TechDetection
from app.services.criticality import attach_criticality
from app.settings import settings


def send_digest_sync(scan_id: int, webhook_url: str | None = None) -> bool:
    async def _send_with_fresh_pool() -> bool:
        # Scanner sync wrappers may have already used the global async engine
        # from a different event loop. Drop inherited pool state before Slack IO.
        await engine.dispose(close=False)
        try:
            return await send_digest(scan_id, webhook_url)
        finally:
            await engine.dispose()

    return asyncio.run(_send_with_fresh_pool())


async def send_digest(scan_id: int, webhook_url: str | None = None) -> bool:
    webhook = webhook_url or os.getenv("WEBHOOK_URL")
    if not webhook:
        return False

    async with SessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        result = await session.execute(
            select(Finding)
            .where(Finding.scan_id == scan_id)
            .options(
                selectinload(Finding.domain),
                selectinload(Finding.validation),
                selectinload(Finding.triage_events),
                selectinload(Finding.secrets),
                selectinload(Finding.tech_detections).selectinload(TechDetection.cves),
            )
            .order_by(Finding.ai_priority.desc(), Finding.last_seen.desc())
        )
        findings = [attach_criticality(item) for item in result.scalars().unique()]
        findings.sort(key=lambda item: (item.criticality_score, item.last_seen, item.id), reverse=True)

    if not scan:
        return False

    urls_scanned = int((scan.stats or {}).get("urls_scanned") or 0)
    outcome = _scan_outcome(scan)
    actionable = [item for item in findings if not _is_suppressed(item)]
    critical_findings = [
        item for item in actionable if item.criticality == "critical" and item.finding_status in {"new", "changed"}
    ]
    high_findings = [
        item for item in actionable if item.criticality == "high" and item.finding_status in {"new", "changed"}
    ]
    needs_triage = [
        item
        for item in actionable
        if not item.validation or item.validation.llm_verdict == "inconclusive"
    ]
    suppressed = [
        item
        for item in findings
        if _is_suppressed(item) and item.validation and item.validation.llm_confidence >= 0.85
    ]

    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"DirHunter scan #{scan.id} {outcome['headline']}"}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Status*\n`{outcome['status']}`"},
                {"type": "mrkdwn", "text": f"*Findings*\n`{len(findings)}`"},
                {"type": "mrkdwn", "text": f"*URLs scanned*\n`{urls_scanned}`"},
                {"type": "mrkdwn", "text": f"*Critical*\n`{len(critical_findings)}`"},
                {"type": "mrkdwn", "text": f"*High*\n`{len(high_findings)}`"},
                {"type": "mrkdwn", "text": f"*Needs triage*\n`{len(needs_triage)}`"},
                {"type": "mrkdwn", "text": f"*Skipped domains*\n`{outcome['skipped']}`"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Links*\n"
                    f"Scan: <{settings.effective_portal_url}/scans/{scan.id}|open scan>\n"
                    f"Dashboard: <{settings.effective_portal_url}|open dashboard>\n"
                    f"Findings queue: <{settings.effective_portal_url}/findings|open findings>\n"
                    f"High priority: <{settings.effective_portal_url}/findings?criticality=high|open high>\n"
                    f"Needs triage: <{settings.effective_portal_url}/findings?verdict=inconclusive|open triage>"
                ),
            },
        },
    ]

    if outcome["skipped"]:
        blocks.extend(_skip_section(outcome))

    if critical_findings:
        blocks.extend(_section("Critical", critical_findings[:3]))
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        "Finding details are summarized in the portal to reduce Slack false-positive noise. "
                        "Use the links above for evidence and triage."
                    ),
                }
            ],
        }
    )
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Auto-suppressed likely false positives: `{len(suppressed)}`",
                }
            ],
        }
    )
    response = requests.post(
        webhook,
        json={
            "text": (
                f"DirHunter scan #{scan.id}: {len(findings)} findings, "
                f"{len(high_findings)} high, {len(needs_triage)} need triage"
            ),
            "blocks": blocks[:50],
            "unfurl_links": False,
            "unfurl_media": False,
        },
        timeout=20,
    )
    return response.status_code == 200


def _scan_outcome(scan: Scan) -> dict[str, Any]:
    stats = scan.stats or {}
    domain_status = stats.get("domain_status") or {}
    domain_errors = stats.get("domain_errors") or {}
    total = int(stats.get("domains_total") or len(domain_status) or 0)
    completed = _count_domain_status(domain_status, "completed")
    failed = _count_domain_status(domain_status, "failed")
    running = _count_domain_status(domain_status, "running")
    queued = _count_domain_status(domain_status, "queued")
    partial_domain_failure = stats.get("error") == "domain_failures" and completed > 0 and failed > 0

    if partial_domain_failure:
        status = "completed_with_skips"
        headline = "completed with skipped domains"
    elif scan.status == "failed":
        status = "failed"
        headline = "failed"
    elif scan.status == "completed":
        status = "completed"
        headline = "complete"
    else:
        status = scan.status
        headline = scan.status

    reason = _skip_reason(domain_errors) if failed else ""
    return {
        "status": status,
        "headline": headline,
        "completed": completed,
        "skipped": failed,
        "running": running,
        "queued": queued,
        "total": total,
        "reason": reason,
        "samples": list(domain_errors.items())[:5],
    }


def _count_domain_status(domain_status: dict[str, Any], status: str) -> int:
    return sum(1 for value in domain_status.values() if value == status)


def _is_suppressed(finding: Finding) -> bool:
    latest_triage = finding.triage_events[-1].label if finding.triage_events else None
    verdict = finding.validation.llm_verdict if finding.validation else None
    return latest_triage == "fp" or verdict == "likely_fp"


def _skip_reason(domain_errors: dict[str, Any]) -> str:
    if not domain_errors:
        return "Some domains did not finish, but completed-domain findings are still valid."

    timeout_count = sum(1 for error in domain_errors.values() if str(error).startswith("timeout:"))
    invalid_count = sum(1 for domain in domain_errors if _looks_dns_validation_record(domain))
    exit_count = sum(1 for error in domain_errors.values() if str(error).startswith("exit_code:"))
    reasons: list[str] = []
    if timeout_count:
        reasons.append(f"{timeout_count} timed out")
    if invalid_count:
        reasons.append(f"{invalid_count} invalid DNS/validation records")
    remaining = len(domain_errors) - timeout_count - invalid_count
    if remaining > 0 and exit_count:
        reasons.append(f"{remaining} DNS/HTTP validation failures")
    if not reasons:
        reasons.append("domain-level scanner failures")
    return "; ".join(reasons) + ". Completed-domain findings are still valid."


def _looks_dns_validation_record(domain: str) -> bool:
    value = domain.lower()
    return value.startswith("_") or "\\052" in value or value.startswith("*") or "._" in value


def _skip_section(outcome: dict[str, Any]) -> list[dict[str, Any]]:
    total = outcome["total"] or outcome["completed"] + outcome["skipped"] + outcome["running"] + outcome["queued"]
    sample_lines = [f"- `{domain}`: `{error}`" for domain, error in outcome["samples"]]
    sample_text = "\n".join(sample_lines) if sample_lines else "No sample available."
    text = (
        f"*Skipped domains*\n"
        f"{outcome['skipped']} of {total} domains were skipped/failed at domain level.\n"
        f"Reason: {outcome['reason']}\n"
        f"Sample:\n{sample_text}"
    )
    return [{"type": "section", "text": {"type": "mrkdwn", "text": text[:3000]}}]


def _section(title: str, findings: list[Finding]) -> list[dict[str, Any]]:
    if not findings:
        return [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*\nNone"}}]

    blocks: list[dict[str, Any]] = [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*"}}]
    for finding in findings:
        domain = finding.domain.host if finding.domain else "unknown"
        confidence = f"{round((finding.validation.llm_confidence if finding.validation else 0) * 100)}%"
        criticality = getattr(finding, "criticality", "low")
        reason = getattr(finding, "criticality_reason", "")
        portal_url = f"{settings.effective_portal_url}/findings?finding={finding.id}"
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{domain}* · `{criticality.upper()}` · `{finding.ai_tag}` · `{finding.finding_status}` · `{confidence}`\n"
                        f"Why: {reason}\n"
                        f"Evidence: {finding.url}\n"
                        f"Portal: <{portal_url}|open finding>"
                    ),
                },
            }
        )
    return blocks

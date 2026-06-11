from __future__ import annotations

import asyncio
import os
from typing import Any

import requests
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import SessionLocal, engine
from app.models import Finding, FindingValidation, Scan, TechDetection
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
        findings = list(result.scalars().unique())

    if not scan:
        return False

    critical = [
        item
        for item in findings
        if item.ai_priority >= 8
        and item.finding_status in {"new", "changed"}
        and (not item.validation or item.validation.llm_verdict == "valid")
    ][:5]
    needs_triage = [
        item
        for item in findings
        if not item.validation or item.validation.llm_verdict == "inconclusive"
    ][:5]
    suppressed = [
        item
        for item in findings
        if item.validation and item.validation.llm_verdict == "likely_fp" and item.validation.llm_confidence >= 0.85
    ]

    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"DirHunter scan #{scan.id} complete"}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Status*\n`{scan.status}`"},
                {"type": "mrkdwn", "text": f"*Findings*\n`{len(findings)}`"},
                {"type": "mrkdwn", "text": f"*Critical*\n`{len(critical)}`"},
                {"type": "mrkdwn", "text": f"*Needs triage*\n`{len(needs_triage)}`"},
            ],
        },
    ]

    blocks.extend(_section("Critical", critical))
    blocks.extend(_section("Needs Triage", needs_triage))
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
    blocks.append(
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Open scan"},
                    "url": f"{settings.effective_portal_url}/scans/{scan.id}",
                    "style": "primary",
                }
            ],
        }
    )

    response = requests.post(
        webhook,
        json={
            "text": f"DirHunter scan #{scan.id}: {len(findings)} findings, {len(needs_triage)} need triage",
            "blocks": blocks[:50],
            "unfurl_links": False,
            "unfurl_media": False,
        },
        timeout=20,
    )
    return response.status_code == 200


def _section(title: str, findings: list[Finding]) -> list[dict[str, Any]]:
    if not findings:
        return [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*\nNone"}}]

    blocks: list[dict[str, Any]] = [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*"}}]
    for finding in findings:
        domain = finding.domain.host if finding.domain else "unknown"
        confidence = f"{round((finding.validation.llm_confidence if finding.validation else 0) * 100)}%"
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{domain}* · `{finding.ai_tag}` · `{finding.finding_status}` · `{confidence}`\n{finding.url}",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Open"},
                    "url": f"{settings.effective_portal_url}/findings?finding={finding.id}",
                },
            }
        )
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Mark FP"},
                        "style": "danger",
                        "value": f"mark_fp:{finding.id}",
                        "action_id": "mark_fp",
                    }
                ],
            }
        )
    return blocks

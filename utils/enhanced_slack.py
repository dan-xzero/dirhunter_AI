"""Compatibility wrapper for the Postgres-backed Slack digest."""

from __future__ import annotations

import os
from typing import Dict, List


def send_enhanced_slack_alert(webhook_url: str, all_domains_data: Dict[str, List[dict]]) -> bool:
    """Send the new single-digest Slack report when SCAN_ID is available.

    The old implementation accepted in-memory findings and generated a verbose
    report. The portal revamp moves digest generation to Postgres so Slack links
    can deep-link to stable finding IDs and interactive triage buttons.
    """
    scan_id = os.getenv("SCAN_ID")
    if not scan_id:
        print("[!] SCAN_ID missing; cannot send Postgres-backed Slack digest")
        return False
    try:
        from app.services.slack import send_digest_sync

        return send_digest_sync(int(scan_id), webhook_url)
    except Exception as exc:
        print(f"[!] Enhanced Slack digest failed: {exc}")
        return False

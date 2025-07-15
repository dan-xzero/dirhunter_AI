# utils/tech_helpers.py
"""Helpers to aggregate technology fingerprints and CVE information
across findings, pages and entire scans.

The tech dict saved in each finding looks like::
    {
        'jQuery': {'version': '3.6.0', ...},
        ...,
        'cve_vulns': 2,
        'cve_details': {
            'jquery': ['CVE-2021-123', ...]
        }
    }

These helpers turn that into badge strings, tables and summary counts
used by the HTML reporter and Slack alerts.
"""
from collections import defaultdict
from typing import Dict, List, Any, Tuple

# ----------------------------------------------------------------------------
# CVE severity helper (very naïve – based on CVE IDs or GHSA ids we cannot
# query CVSS without another API call). For now classify by number of vulns.
# ----------------------------------------------------------------------------


def severity_from_count(count: int) -> str:
    if count >= 5:
        return "Critical"
    if count >= 3:
        return "High"
    if count == 2:
        return "Medium"
    return "Low"


# ----------------------------------------------------------------------------
# Per-finding helpers
# ----------------------------------------------------------------------------


def extract_tech_and_cves(tech_dict: Dict[str, Any]) -> Tuple[List[str], Dict[str, Any]]:
    """Return list of tech badge strings and cve summary dict."""
    if not tech_dict:
        return [], {}

    badges: List[str] = []
    cve_summary: Dict[str, Any] = {}

    # Iterate over individual tech entries (skip meta keys)
    for name, meta in tech_dict.items():
        if name in {"cve_vulns", "cve_details"}:
            continue
        version = meta.get("version", "") if isinstance(meta, dict) else ""
        badge = f"{name} {version}".strip()
        badges.append(badge)

    # CVE aggregation
    # Use cve_details directly – fall back to cve_vulns only for counts.
    total_cves = tech_dict.get("cve_vulns", 0) or 0
    details: Dict[str, Any] = tech_dict.get("cve_details", {}) or {}

    # If no explicit details but there is a total count, we cannot build table
    # so skip in that case. Otherwise iterate over details.
    if details:
        for pkg, info in details.items():
            if isinstance(info, dict):
                ids = info.get("ids", [])
                version = info.get("version", "")
            else:
                ids = info
                version = ""
            # Use per-package count for base severity but elevate slightly
            # so that packages with exactly 2 CVEs are treated as *High*
            base_sev = severity_from_count(len(ids))
            if base_sev == "Medium" and len(ids) == 2:
                base_sev = "High"

            cve_summary[pkg] = {
                "count": len(ids),
                "ids": ids,
                "version": version,
                "severity": base_sev,
            }

    # If for some reason details missing but legacy cve_vulns exists, keep the
    # total so callers can still build summary counts (they will fall back to
    # download_meta for full details).
    if not cve_summary and tech_dict.get("cve_vulns"):
        cve_summary["_total"] = {
            "count": tech_dict.get("cve_vulns", 0),
            "ids": [],
            "version": "",
            "severity": severity_from_count(tech_dict.get("cve_vulns", 0)),
        }

    return badges, cve_summary


# ----------------------------------------------------------------------------
# Aggregation across many findings
# ----------------------------------------------------------------------------


def aggregate_cves(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return dict with total and unique CVE details across a list of findings."""
    summary: Dict[str, Any] = {"total": 0, "packages": {}}

    for f in findings:
        tech = f.get("tech") or {}
        _, cves = extract_tech_and_cves(tech)
        for pkg, info in cves.items():
            existing = summary["packages"].get(pkg)
            if existing:
                # Merge ids set
                combined = set(existing["ids"]) | set(info["ids"])
                existing["ids"] = list(combined)
                existing["count"] = len(combined)
                if not existing.get("version"):
                    existing["version"] = info.get("version")
            else:
                summary["packages"][pkg] = info

    # total unique CVEs
    all_ids = {cid for info in summary["packages"].values() for cid in info["ids"]}
    summary["total"] = len(all_ids)
    return summary 
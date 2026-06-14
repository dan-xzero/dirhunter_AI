from __future__ import annotations

from dataclasses import dataclass

from app.models import Finding


HIGH_RISK_TERMS = (
    "admin",
    "actuator",
    "config",
    "debug",
    "dump",
    "env",
    "error.txt",
    "health",
    "internal",
    "metrics",
    "secret",
    "swagger",
    "token",
)

LEVEL_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class Criticality:
    level: str
    score: int
    reason: str


def score_finding(finding: Finding) -> Criticality:
    latest_triage = finding.triage_events[-1].label if finding.triage_events else None
    verdict = finding.validation.llm_verdict if finding.validation else None
    confidence = finding.validation.llm_confidence if finding.validation else 0.0

    if latest_triage == "fp" or verdict == "likely_fp":
        return Criticality("low", 0, "Likely false positive based on LLM or human triage.")

    score = 0
    reasons: list[str] = []
    cves = [cve for tech in finding.tech_detections for cve in tech.cves]
    severities = {(cve.severity or "").lower() for cve in cves}

    if finding.secrets:
        score += 4
        reasons.append("secret evidence")
    if "critical" in severities:
        score += 4
        reasons.append("critical CVE")
    elif "high" in severities:
        score += 3
        reasons.append("high CVE")

    if verdict == "valid":
        score += 3 if confidence >= 0.85 else 2
        reasons.append("LLM valid")
    elif verdict == "inconclusive":
        score += 1
        reasons.append("LLM inconclusive")

    if finding.finding_status == "new":
        score += 1
        reasons.append("new exposure")
    elif finding.content_changed:
        score += 1
        reasons.append("changed content")

    high_risk_text = " ".join(
        value
        for value in (
            finding.url,
            finding.ai_tag,
            finding.validation.category_corrected if finding.validation else None,
            finding.validation.llm_reasoning if finding.validation else None,
        )
        if value
    ).lower()
    high_risk_term = next((term for term in HIGH_RISK_TERMS if term in high_risk_text), None)
    if high_risk_term:
        score += 1
        reasons.append(f"sensitive path: {high_risk_term}")

    if finding.ai_priority >= 4:
        score += 2
        reasons.append("high scanner priority")
    elif finding.ai_priority >= 2:
        score += 1

    if score >= 7:
        level = "critical"
    elif score >= 4:
        level = "high"
    elif score >= 2:
        level = "medium"
    else:
        level = "low"

    return Criticality(level, score, ", ".join(reasons[:3]) or "Low confidence or low-impact signal.")


def attach_criticality(finding: Finding) -> Finding:
    criticality = score_finding(finding)
    finding.criticality = criticality.level
    finding.criticality_score = criticality.score
    finding.criticality_reason = criticality.reason
    return finding


def criticality_rank(level: str | None) -> int:
    return LEVEL_RANK.get((level or "").lower(), 0)

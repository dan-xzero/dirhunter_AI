from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class DomainOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    host: str
    env: str
    tags: list[str]


class ValidationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    llm_verdict: str
    llm_confidence: float
    llm_reasoning: str | None = None
    category_corrected: str | None = None
    model: str
    tokens_used: int
    cost_usd: float
    validated_at: datetime


class TriageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user: str
    label: str
    note: str | None = None
    labeled_at: datetime


class SecretOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    type: str
    risk: str
    snippet: str | None = None
    reason: str | None = None


class CVEOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    severity: str | None = None


class TechDetectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    version: str | None = None
    source: str | None = None
    confidence: float
    cves: list[CVEOut] = []


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int | None
    domain: DomainOut
    url: str
    path: str | None = None
    status_code: int | None = None
    content_length: int | None = None
    sha1_hash: str | None = None
    fuzzy_hash: str | None = None
    ai_tag: str
    ai_priority: int
    finding_status: str
    first_seen: datetime
    last_seen: datetime
    times_seen: int
    content_changed: bool
    screenshot_path: str | None = None
    headers: dict[str, Any]
    body_excerpt: str | None = None
    download_meta: dict[str, Any]
    validation: ValidationOut | None = None
    triage_events: list[TriageOut] = []
    secrets: list[SecretOut] = []
    tech_detections: list[TechDetectionOut] = []
    similar_fp_count: int = 0


class FindingListOut(BaseModel):
    items: list[FindingOut]
    total: int
    limit: int
    offset: int


class OverviewStatsOut(BaseModel):
    total_scans: int
    total_findings: int
    validated_findings: int
    legacy_findings: int
    actionable_findings: int
    needs_triage: int
    valid_count: int
    likely_fp_count: int
    human_fp_label_ratio: float
    triage_label_count: int
    latest_scan: dict[str, Any] | None = None
    by_status: dict[str, int]
    raw_by_status: dict[str, int]
    by_verdict: dict[str, int]


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    started_at: datetime
    finished_at: datetime | None = None
    trigger: str
    status: str
    wordlist: str | None = None
    args: dict[str, Any]
    stats: dict[str, Any]
    status_breakdown: dict[str, int] | None = None


class TriageIn(BaseModel):
    label: str
    note: str | None = None
    user: str = "portal"


class ScanCreateIn(BaseModel):
    domains: str | None = None
    wordlist: str | None = None
    args: list[str] = []

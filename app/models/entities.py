from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trigger: Mapped[str] = mapped_column(String(32), default="manual", index=True)
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)
    wordlist: Mapped[str | None] = mapped_column(Text, nullable=True)
    args: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Domain(Base, TimestampMixin):
    __tablename__ = "domains"
    __table_args__ = (UniqueConstraint("host", name="uq_domains_host"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    env: Mapped[str] = mapped_column(String(32), default="unknown", index=True)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)

    findings: Mapped[list["Finding"]] = relationship(back_populates="domain")


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("url", "sha1_hash", name="uq_findings_url_sha1"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(Text, index=True)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    content_length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha1_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    fuzzy_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_tag: Mapped[str] = mapped_column(String(128), default="Other", index=True)
    ai_priority: Mapped[int] = mapped_column(Integer, default=0, index=True)
    finding_status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    times_seen: Mapped[int] = mapped_column(Integer, default=1)
    content_changed: Mapped[bool] = mapped_column(Boolean, default=False)
    screenshot_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    headers: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    body_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    download_meta: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)

    scan: Mapped[Scan | None] = relationship(back_populates="findings")
    domain: Mapped[Domain] = relationship(back_populates="findings")
    validation: Mapped["FindingValidation | None"] = relationship(
        back_populates="finding", cascade="all, delete-orphan", uselist=False
    )
    triage_events: Mapped[list["FindingTriage"]] = relationship(back_populates="finding", cascade="all, delete-orphan")
    secrets: Mapped[list["Secret"]] = relationship(back_populates="finding", cascade="all, delete-orphan")
    tech_detections: Mapped[list["TechDetection"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class FindingValidation(Base, TimestampMixin):
    __tablename__ = "findings_validation"
    __table_args__ = (UniqueConstraint("finding_id", name="uq_findings_validation_finding"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    llm_verdict: Mapped[str] = mapped_column(String(32), default="inconclusive", index=True)
    llm_confidence: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    llm_reasoning: Mapped[str | None] = mapped_column(Text, nullable=True)
    category_corrected: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model: Mapped[str] = mapped_column(String(128), default="unknown")
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    finding: Mapped[Finding] = relationship(back_populates="validation")


class FindingTriage(Base, TimestampMixin):
    __tablename__ = "findings_triage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    user: Mapped[str] = mapped_column(String(255), default="system", index=True)
    label: Mapped[str] = mapped_column(String(32), index=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    labeled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    finding: Mapped[Finding] = relationship(back_populates="triage_events")


class Secret(Base, TimestampMixin):
    __tablename__ = "secrets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(128), default="unknown", index=True)
    risk: Mapped[str] = mapped_column(String(32), default="medium", index=True)
    snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    finding: Mapped[Finding] = relationship(back_populates="secrets")


class TechDetection(Base, TimestampMixin):
    __tablename__ = "tech_detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, index=True)

    finding: Mapped[Finding] = relationship(back_populates="tech_detections")
    cves: Mapped[list["CVE"]] = relationship(back_populates="tech_detection", cascade="all, delete-orphan")


class CVE(Base, TimestampMixin):
    __tablename__ = "cves"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tech_detection_id: Mapped[int] = mapped_column(ForeignKey("tech_detections.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    tech_detection: Mapped[TechDetection] = relationship(back_populates="cves")


class EndpointHash(Base):
    __tablename__ = "endpoint_hashes"

    url: Mapped[str] = mapped_column(Text, primary_key=True)
    sha1: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(255), default="system", index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    target_type: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

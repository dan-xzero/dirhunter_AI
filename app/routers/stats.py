from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Finding, FindingTriage, FindingValidation, Scan
from app.schemas import OverviewStatsOut, ScanOut

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("/overview", response_model=OverviewStatsOut)
async def overview(session: AsyncSession = Depends(get_session)) -> OverviewStatsOut:
    latest_triage_label = (
        select(FindingTriage.label)
        .where(FindingTriage.finding_id == Finding.id)
        .order_by(FindingTriage.labeled_at.desc(), FindingTriage.id.desc())
        .limit(1)
        .correlate(Finding)
        .scalar_subquery()
    )
    total_scans = (await session.execute(select(func.count()).select_from(Scan))).scalar_one()
    total_findings = (await session.execute(select(func.count()).select_from(Finding))).scalar_one()
    validated_findings = (
        await session.execute(
            select(func.count())
            .select_from(Finding)
            .join(FindingValidation, FindingValidation.finding_id == Finding.id)
        )
    ).scalar_one()
    legacy_findings = (
        await session.execute(
            select(func.count())
            .select_from(Finding)
            .join(FindingValidation, FindingValidation.finding_id == Finding.id, isouter=True)
            .where(FindingValidation.id.is_(None))
        )
    ).scalar_one()
    actionable_findings = (
        await session.execute(
            select(func.count())
            .select_from(Finding)
            .join(FindingValidation, FindingValidation.finding_id == Finding.id)
            .where(FindingValidation.llm_verdict != "likely_fp")
            .where(or_(latest_triage_label.is_(None), latest_triage_label != "fp"))
        )
    ).scalar_one()
    needs_triage = (
        await session.execute(
            select(func.count())
            .select_from(Finding)
            .join(FindingValidation, FindingValidation.finding_id == Finding.id)
            .where(FindingValidation.llm_verdict == "inconclusive")
            .where(or_(latest_triage_label.is_(None), latest_triage_label != "fp"))
        )
    ).scalar_one()
    valid_count = (
        await session.execute(
            select(func.count())
            .select_from(Finding)
            .join(FindingValidation, FindingValidation.finding_id == Finding.id)
            .where(FindingValidation.llm_verdict == "valid")
            .where(or_(latest_triage_label.is_(None), latest_triage_label != "fp"))
        )
    ).scalar_one()
    likely_fp_count = (
        await session.execute(
            select(func.count())
            .select_from(Finding)
            .join(FindingValidation, FindingValidation.finding_id == Finding.id)
            .where(or_(FindingValidation.llm_verdict == "likely_fp", latest_triage_label == "fp"))
        )
    ).scalar_one()
    false_positive_labels = (
        await session.execute(select(func.count()).select_from(FindingTriage).where(FindingTriage.label == "fp"))
    ).scalar_one()
    triage_labels = (await session.execute(select(func.count()).select_from(FindingTriage))).scalar_one()
    human_fp_label_ratio = (false_positive_labels / triage_labels) if triage_labels else 0.0
    latest_scan = (
        await session.execute(select(Scan).order_by(Scan.started_at.desc()).limit(1))
    ).scalars().first()
    latest_scan_payload = None
    if latest_scan:
        latest_breakdown = (
            await session.execute(
                select(Finding.finding_status, func.count())
                .where(Finding.scan_id == latest_scan.id)
                .group_by(Finding.finding_status)
            )
        ).all()
        latest_breakdown_dict = dict(latest_breakdown)
        latest_scan_payload = ScanOut.model_validate(latest_scan).model_dump(mode="json")
        latest_scan_payload["status_breakdown"] = {
            "new": latest_breakdown_dict.get("new", 0),
            "recurring": latest_breakdown_dict.get("existing", 0),
            "changed": latest_breakdown_dict.get("changed", 0),
        }

    by_status = (
        await session.execute(
            select(Finding.finding_status, func.count())
            .join(FindingValidation, FindingValidation.finding_id == Finding.id)
            .where(FindingValidation.llm_verdict != "likely_fp")
            .where(or_(latest_triage_label.is_(None), latest_triage_label != "fp"))
            .group_by(Finding.finding_status)
        )
    ).all()
    raw_by_status = (
        await session.execute(select(Finding.finding_status, func.count()).group_by(Finding.finding_status))
    ).all()
    by_verdict = (
        await session.execute(select(FindingValidation.llm_verdict, func.count()).group_by(FindingValidation.llm_verdict))
    ).all()

    return OverviewStatsOut(
        total_scans=total_scans,
        total_findings=total_findings,
        validated_findings=validated_findings,
        legacy_findings=legacy_findings,
        actionable_findings=actionable_findings,
        needs_triage=needs_triage,
        valid_count=valid_count,
        likely_fp_count=likely_fp_count,
        human_fp_label_ratio=human_fp_label_ratio,
        triage_label_count=triage_labels,
        latest_scan=latest_scan_payload,
        by_status=dict(by_status),
        raw_by_status=dict(raw_by_status),
        by_verdict=dict(by_verdict),
    )

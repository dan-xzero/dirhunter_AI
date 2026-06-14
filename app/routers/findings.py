from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased
from sqlalchemy.orm import selectinload

from app.auth import Actor, current_actor
from app.db import get_session
from app.models import Finding, FindingTriage, TechDetection
from app.schemas import FindingListOut, FindingOut, TriageIn, TriageOut
from app.services.criticality import attach_criticality
from app.services.findings import add_triage, list_findings, upsert_validation

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=FindingListOut)
async def get_findings(
    scan_id: int | None = None,
    domain: str | None = None,
    status: str | None = None,
    tag: str | None = None,
    triage: str | None = None,
    verdict: str | None = None,
    criticality: str | None = None,
    include_likely_fp: bool = False,
    include_unvalidated: bool = False,
    q: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> FindingListOut:
    items, total = await list_findings(
        session,
        scan_id=scan_id,
        domain=domain,
        status=status,
        tag=tag,
        triage=triage,
        verdict=verdict,
        criticality=criticality,
        include_likely_fp=include_likely_fp,
        include_unvalidated=include_unvalidated,
        q=q,
        limit=limit,
        offset=offset,
    )
    return FindingListOut(items=items, total=total, limit=limit, offset=offset)


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: int, session: AsyncSession = Depends(get_session)) -> Finding:
    stmt = (
        select(Finding)
        .where(Finding.id == finding_id)
        .options(
            selectinload(Finding.domain),
            selectinload(Finding.validation),
            selectinload(Finding.triage_events),
            selectinload(Finding.secrets),
            selectinload(Finding.tech_detections).selectinload(TechDetection.cves),
        )
    )
    finding = (await session.execute(stmt)).scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="finding not found")
    finding.similar_fp_count = await _similar_fp_count(session, finding)
    return attach_criticality(finding)


async def _similar_fp_count(session: AsyncSession, finding: Finding) -> int:
    candidate = aliased(Finding)
    latest_label = (
        select(FindingTriage.label)
        .where(FindingTriage.finding_id == candidate.id)
        .order_by(FindingTriage.labeled_at.desc(), FindingTriage.id.desc())
        .limit(1)
        .correlate(candidate)
        .scalar_subquery()
    )
    similarity = [candidate.url == finding.url]
    if finding.path:
        similarity.append(and_(candidate.path == finding.path, candidate.ai_tag == finding.ai_tag))
    result = await session.execute(
        select(func.count())
        .select_from(candidate)
        .where(candidate.id != finding.id)
        .where(or_(*similarity))
        .where(latest_label == "fp")
    )
    return int(result.scalar_one() or 0)


@router.post("/{finding_id}/triage", response_model=TriageOut)
async def triage_finding(
    finding_id: int,
    payload: TriageIn,
    actor: Actor = Depends(current_actor),
    session: AsyncSession = Depends(get_session),
) -> TriageOut:
    if payload.label not in {"tp", "fp", "needs_review"}:
        raise HTTPException(status_code=422, detail="label must be tp, fp, or needs_review")
    if not await session.get(Finding, finding_id):
        raise HTTPException(status_code=404, detail="finding not found")
    user = payload.user if payload.user != "portal" else actor.email
    return await add_triage(finding_id=finding_id, label=payload.label, user=user, note=payload.note)


@router.post("/{finding_id}/revalidate", response_model=FindingOut)
async def revalidate_finding(
    finding_id: int,
    session: AsyncSession = Depends(get_session),
    _actor: Actor = Depends(current_actor),
) -> Finding:
    finding = await get_finding(finding_id, session)
    from utils.llm_validator import validate_batch

    raw = dict(finding.raw or {})
    raw.setdefault("url", finding.url)
    raw.setdefault("ai_tag", finding.ai_tag)
    raw.setdefault("status", finding.status_code)
    raw.setdefault("length", finding.content_length)
    raw.setdefault("body_excerpt", finding.body_excerpt)
    raw.setdefault("headers", finding.headers)
    validated_items = await run_in_threadpool(validate_batch, [raw])
    if not validated_items:
        raise HTTPException(status_code=502, detail="LLM validation returned no result")

    validated = validated_items[0]
    if validated.get("llm_validation"):
        await upsert_validation(session, finding.id, validated["llm_validation"])
        await session.commit()
        session.expire_all()
    else:
        raise HTTPException(status_code=502, detail="LLM validation returned no validation payload")

    refreshed = await get_finding(finding_id, session)
    return refreshed

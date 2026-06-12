from fastapi import APIRouter, Depends, HTTPException, Query
from app.auth import Actor, current_actor
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Finding, Scan
from app.schemas import ScanCreateIn, ScanOut
from app.services.scan_runner import enqueue_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("", response_model=dict)
async def list_scans(
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> dict:
    total = (await session.execute(select(func.count()).select_from(Scan))).scalar_one()
    result = await session.execute(select(Scan).order_by(Scan.started_at.desc()).limit(limit).offset(offset))
    scans = list(result.scalars())
    breakdowns = await _status_breakdowns(session, [scan.id for scan in scans])
    return {
        "items": [_scan_out(scan, breakdowns.get(scan.id)) for scan in scans],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: int, session: AsyncSession = Depends(get_session)) -> dict:
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    breakdowns = await _status_breakdowns(session, [scan_id])
    return _scan_out(scan, breakdowns.get(scan_id))


@router.post("", response_model=ScanOut)
async def create_scan_record(
    payload: ScanCreateIn,
    session: AsyncSession = Depends(get_session),
    _actor: Actor = Depends(current_actor),
) -> Scan:
    try:
        scan_id = await enqueue_scan(domains=payload.domains, wordlist=payload.wordlist, args=payload.args)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=500, detail="scan creation failed")
    return _scan_out(scan, _empty_breakdown())


def _empty_breakdown() -> dict[str, int]:
    return {"new": 0, "recurring": 0, "changed": 0}


def _normalized_breakdown(raw: dict[str, int] | None) -> dict[str, int]:
    raw = raw or {}
    return {
        "new": raw.get("new", 0),
        "recurring": raw.get("existing", 0),
        "changed": raw.get("changed", 0),
    }


async def _status_breakdowns(session: AsyncSession, scan_ids: list[int]) -> dict[int, dict[str, int]]:
    if not scan_ids:
        return {}
    result = await session.execute(
        select(Finding.scan_id, Finding.finding_status, func.count())
        .where(Finding.scan_id.in_(scan_ids))
        .group_by(Finding.scan_id, Finding.finding_status)
    )
    raw: dict[int, dict[str, int]] = {}
    for scan_id, status, count in result.all():
        if scan_id is None:
            continue
        raw.setdefault(scan_id, {})[status] = count
    return {scan_id: _normalized_breakdown(raw.get(scan_id)) for scan_id in scan_ids}


def _scan_out(scan: Scan, breakdown: dict[str, int] | None) -> dict:
    payload = ScanOut.model_validate(scan).model_dump(mode="json")
    payload["status_breakdown"] = breakdown or _empty_breakdown()
    return payload

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Finding
from app.settings import settings

router = APIRouter(prefix="/api/screenshots", tags=["screenshots"])


@router.get("/{finding_id}")
async def screenshot(finding_id: int, session: AsyncSession = Depends(get_session)) -> FileResponse:
    finding = await session.get(Finding, finding_id)
    if not finding or not finding.screenshot_path:
        raise HTTPException(status_code=404, detail="screenshot not found")

    path = Path(finding.screenshot_path)
    if not path.is_absolute():
        path = Path.cwd() / path

    screenshot_root = settings.screenshot_root
    if not screenshot_root.is_absolute():
        screenshot_root = Path.cwd() / screenshot_root

    try:
        path.resolve().relative_to(screenshot_root.resolve())
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="screenshot path outside allowed root") from exc

    if not path.exists():
        raise HTTPException(status_code=404, detail="screenshot file missing")

    return FileResponse(path)

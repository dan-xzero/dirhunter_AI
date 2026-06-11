import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select

from app.db import SessionLocal
from app.models import Finding, Scan

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress(websocket: WebSocket, scan_id: int) -> None:
    await websocket.accept()
    try:
        while True:
            async with SessionLocal() as session:
                scan = await session.get(Scan, scan_id)
                finding_count = (
                    await session.execute(select(func.count()).select_from(Finding).where(Finding.scan_id == scan_id))
                ).scalar_one()
                if not scan:
                    await websocket.send_json({"error": "scan not found"})
                    return
                await websocket.send_json(
                    {
                        "id": scan.id,
                        "status": scan.status,
                        "started_at": scan.started_at.isoformat(),
                        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                        "stats": scan.stats or {},
                        "finding_count": finding_count,
                    }
                )
                if scan.status in {"completed", "failed", "cancelled"}:
                    return
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        return

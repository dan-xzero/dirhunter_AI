#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import SessionLocal
from app.models import Scan
from app.services.scan_runner import enqueue_scan_resume


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resume failed or abandoned DirHunter scans.")
    parser.add_argument("--interval", type=int, default=int(os.getenv("SCAN_WATCHDOG_INTERVAL", "300")))
    parser.add_argument("--stale-minutes", type=int, default=int(os.getenv("SCAN_WATCHDOG_STALE_MINUTES", "45")))
    parser.add_argument("--max-attempts", type=int, default=int(os.getenv("SCAN_WATCHDOG_MAX_ATTEMPTS", "3")))
    parser.add_argument("--once", action="store_true", help="Run one check and exit.")
    return parser.parse_args()


async def find_resume_candidates(stale_minutes: int, max_attempts: int) -> list[tuple[int, str]]:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=stale_minutes)
    candidates: list[tuple[int, str]] = []
    async with SessionLocal() as session:
        result = await session.execute(
            select(Scan).where(Scan.status.in_(["failed", "running"])).order_by(Scan.started_at.desc()).limit(100)
        )
        for scan in result.scalars():
            stats = scan.stats or {}
            if stats.get("resume_disabled"):
                continue
            attempts = int(stats.get("resume_attempts") or 0)
            if attempts >= max_attempts:
                continue
            if scan.status == "failed":
                candidates.append((scan.id, "failed"))
                continue
            if scan.status == "running" and scan.started_at and scan.started_at < cutoff:
                pid = stats.get("pid")
                if not _pid_alive(pid):
                    candidates.append((scan.id, "stale_running"))
    return candidates


async def resume_once(stale_minutes: int, max_attempts: int) -> int:
    resumed = 0
    for scan_id, reason in await find_resume_candidates(stale_minutes, max_attempts):
        if await enqueue_scan_resume(scan_id, reason=reason):
            print(f"resumed scan {scan_id} reason={reason}", flush=True)
            resumed += 1
    if resumed == 0:
        print("no scans needed resume", flush=True)
    return resumed


def _pid_alive(pid: object) -> bool:
    try:
        value = int(pid)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    try:
        os.kill(value, 0)
        return True
    except OSError:
        return False


async def main() -> None:
    args = parse_args()
    stop = asyncio.Event()

    def _stop(*_: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while not stop.is_set():
        await resume_once(args.stale_minutes, args.max_attempts)
        if args.once:
            return
        try:
            await asyncio.wait_for(stop.wait(), timeout=args.interval)
        except asyncio.TimeoutError:
            pass


if __name__ == "__main__":
    asyncio.run(main())

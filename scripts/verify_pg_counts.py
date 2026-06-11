#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, select

from app.db import SessionLocal
from app.models import EndpointHash, Finding


def sqlite_counts(path: Path) -> dict[str, int]:
    counts = {"endpoint_hashes": 0, "finding_history": 0}
    if not path.exists():
        return counts
    with sqlite3.connect(path) as conn:
        for table in counts:
            try:
                counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.Error:
                counts[table] = 0
    return counts


async def pg_counts() -> dict[str, int]:
    async with SessionLocal() as session:
        endpoint_hashes = (await session.execute(select(func.count()).select_from(EndpointHash))).scalar_one()
        findings = (await session.execute(select(func.count()).select_from(Finding))).scalar_one()
        return {"endpoint_hashes": endpoint_hashes, "findings": findings}


async def main() -> None:
    legacy = sqlite_counts(Path("db/endpoint_hashes.sqlite"))
    pg = await pg_counts()
    print("Legacy SQLite:", legacy)
    print("Postgres:", pg)
    if legacy["endpoint_hashes"] and pg["endpoint_hashes"] < legacy["endpoint_hashes"]:
        raise SystemExit("Postgres endpoint hash count is lower than legacy SQLite")


if __name__ == "__main__":
    asyncio.run(main())

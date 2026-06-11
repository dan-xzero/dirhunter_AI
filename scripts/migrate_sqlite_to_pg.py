#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy.dialects.postgresql import insert

from app.db import SessionLocal
from app.models import EndpointHash
from app.services.serialization import clean_text
from app.services.findings import create_scan, persist_batch


async def migrate_endpoint_hashes(sqlite_path: Path) -> int:
    if not sqlite_path.exists():
        return 0

    rows = []
    with sqlite3.connect(sqlite_path) as conn:
        conn.row_factory = sqlite3.Row
        for row in conn.execute("SELECT url, sha1, last_seen FROM endpoint_hashes"):
            rows.append({"url": clean_text(row["url"]), "sha1": clean_text(row["sha1"]), "last_seen": parse_dt(row["last_seen"])})

    if not rows:
        return 0

    async with SessionLocal() as session:
        for row in rows:
            await session.execute(
                insert(EndpointHash)
                .values(**row)
                .on_conflict_do_update(
                    index_elements=[EndpointHash.url],
                    set_={"sha1": row["sha1"], "last_seen": row["last_seen"]},
                )
            )
        await session.commit()

    return len(rows)


async def migrate_enriched_findings(enriched_dir: Path) -> int:
    if not enriched_dir.exists():
        return 0

    scan_id = await create_scan(trigger="migration", args={"source": str(enriched_dir)}, status="completed")
    all_results: dict[str, list[dict]] = {}
    for path in sorted(enriched_dir.glob("*_enriched.json")):
        domain = path.name.removesuffix("_enriched.json")
        try:
            findings = json.loads(path.read_text())
        except Exception as exc:
            print(f"[!] Skipping {path}: {exc}")
            continue
        if isinstance(findings, list):
            all_results[domain] = findings

    stats = await persist_batch(scan_id, all_results)
    return stats.get("findings", 0)


def parse_dt(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            return None
    return None


async def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate DirHunter SQLite/hash state and enriched JSON into Postgres")
    parser.add_argument("--sqlite", default="db/endpoint_hashes.sqlite", help="Path to legacy SQLite DB")
    parser.add_argument("--enriched-dir", default="results/html/enriched", help="Path to enriched finding JSON files")
    parser.add_argument("--hashes-only", action="store_true", help="Only migrate endpoint_hashes")
    args = parser.parse_args()

    hash_count = await migrate_endpoint_hashes(Path(args.sqlite))
    finding_count = 0
    if not args.hashes_only:
        finding_count = await migrate_enriched_findings(Path(args.enriched_dir))

    print(f"[+] Migrated {hash_count} endpoint hashes")
    print(f"[+] Migrated {finding_count} findings")


if __name__ == "__main__":
    asyncio.run(main())

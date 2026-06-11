#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db import SessionLocal
from app.models import Finding, FindingTriage


async def export_examples(output_path: Path, limit: int = 500) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    async with SessionLocal() as session:
        result = await session.execute(
            select(FindingTriage)
            .options(selectinload(FindingTriage.finding).selectinload(Finding.domain))
            .order_by(FindingTriage.labeled_at.desc())
            .limit(limit)
        )
        events = list(result.scalars())

    with output_path.open("w", encoding="utf-8") as handle:
        for event in reversed(events):
            finding = event.finding
            handle.write(
                json.dumps(
                    {
                        "url": finding.url,
                        "domain": finding.domain.host if finding.domain else None,
                        "ai_tag": finding.ai_tag,
                        "status": finding.status_code,
                        "length": finding.content_length,
                        "body_excerpt": (finding.body_excerpt or "")[:600],
                        "human_label": event.label,
                        "note": event.note,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    return len(events)


async def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/triage_examples.jsonl")
    count = await export_examples(output)
    print(f"[+] Exported {count} triage examples to {output}")


if __name__ == "__main__":
    asyncio.run(main())

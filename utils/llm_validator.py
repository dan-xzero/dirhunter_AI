from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from config import OPENAI_MODEL_FALLBACK, OPENAI_MODEL_VALIDATOR

logger = logging.getLogger(__name__)
load_dotenv(override=True)

VALIDATION_SCHEMA = {
    "name": "dirhunter_finding_validation",
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "index": {"type": "integer"},
                        "verdict": {"type": "string", "enum": ["valid", "likely_fp", "inconclusive"]},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "reason": {"type": "string"},
                        "category_corrected": {"type": "string"},
                    },
                    "required": ["index", "verdict", "confidence", "reason", "category_corrected"],
                },
            }
        },
        "required": ["items"],
    },
    "strict": True,
}


def _client() -> OpenAI | None:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.warning("OPENAI_API_KEY missing; LLM finding validation disabled")
        return None
    return OpenAI(api_key=api_key)


def validate_batch(
    findings: list[dict[str, Any]],
    *,
    batch_size: int = 8,
    budget_usd: float | None = None,
    examples_path: str | Path = "data/triage_examples.jsonl",
) -> list[dict[str, Any]]:
    """Validate findings with GPT-5.5 and attach `llm_validation` to each item."""
    client = _client()
    if not client or not findings:
        return findings

    remaining_budget = budget_usd if budget_usd is not None else float(os.getenv("LLM_BUDGET_USD", "25"))
    examples = _load_examples(Path(examples_path), limit=8)
    output: list[dict[str, Any]] = []

    for start in range(0, len(findings), batch_size):
        chunk = findings[start : start + batch_size]
        if remaining_budget <= 0:
            manual_fp_urls = _load_manual_fp_urls(chunk)
            for item in chunk:
                item["llm_validation"] = _heuristic_fallback(item, reason="budget exhausted")
                _apply_manual_fp_override(item, manual_fp_urls)
            output.extend(chunk)
            continue

        try:
            validations, tokens = _validate_chunk(client, chunk, examples, OPENAI_MODEL_VALIDATOR)
        except Exception as exc:
            logger.warning("Validator failed with %s; retrying fallback model", OPENAI_MODEL_VALIDATOR)
            try:
                validations, tokens = _validate_chunk(client, chunk, examples, OPENAI_MODEL_FALLBACK)
            except Exception as fallback_exc:
                logger.error("LLM validation failed: %s / %s", exc, fallback_exc)
                validations = [_heuristic_fallback(item, reason=str(fallback_exc)) for item in chunk]
                tokens = 0

        estimated_cost = _estimate_cost(tokens)
        remaining_budget -= estimated_cost
        by_index = {item["index"]: item for item in validations if "index" in item}
        manual_fp_urls = _load_manual_fp_urls(chunk)
        for index, finding in enumerate(chunk):
            validation = by_index.get(index) or _heuristic_fallback(finding, reason="missing model response")
            validation.setdefault("model", OPENAI_MODEL_VALIDATOR)
            validation.setdefault("tokens_used", tokens // max(len(chunk), 1))
            validation.setdefault("cost_usd", estimated_cost / max(len(chunk), 1))
            finding["llm_validation"] = validation
            _apply_manual_fp_override(finding, manual_fp_urls)
            output.append(finding)

    return output


def _validate_chunk(
    client: OpenAI,
    chunk: list[dict[str, Any]],
    examples: list[dict[str, Any]],
    model: str,
) -> tuple[list[dict[str, Any]], int]:
    prompt = {
        "task": "Classify each DirHunter web finding as valid, likely_fp, or inconclusive. Be conservative: suppress only obvious false positives.",
        "rules": [
            "valid means a human security reviewer should inspect it.",
            "likely_fp means generic noise, duplicate soft-404, empty boilerplate, or no security value.",
            "inconclusive means there is not enough evidence.",
            "Never mark credentials/secrets, admin panels, database tools, source code, config, logs, or sensitive files as likely_fp unless evidence is clearly bogus.",
        ],
        "examples": examples,
        "findings": [_finding_payload(i, item) for i, item in enumerate(chunk)],
    }
    response = client.chat.completions.create(
        model=model,
        response_format={"type": "json_schema", "json_schema": VALIDATION_SCHEMA},
        messages=[
            {"role": "system", "content": "You are a senior application security triage analyst."},
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
        ],
    )
    content = response.choices[0].message.content or '{"items":[]}'
    parsed = json.loads(content)
    usage = getattr(response, "usage", None)
    tokens = int(getattr(usage, "total_tokens", 0) or 0)
    items = parsed.get("items", [])
    for item in items:
        item["model"] = model
    return items, tokens


def _finding_payload(index: int, item: dict[str, Any]) -> dict[str, Any]:
    headers = item.get("headers") or {}
    download_meta = item.get("download_meta") or {}
    return {
        "index": index,
        "url": item.get("url"),
        "status": item.get("status") or item.get("final_status"),
        "length": item.get("length") or item.get("content_length"),
        "ai_tag": item.get("ai_tag"),
        "finding_status": item.get("finding_status"),
        "headers": {k: headers[k] for k in list(headers)[:12]},
        "body_excerpt": _body_excerpt(item),
        "download_meta": download_meta,
        "tech": item.get("tech") or {},
    }


def _body_excerpt(item: dict[str, Any], max_chars: int = 1500) -> str:
    for key in ("body_excerpt", "page_text", "text", "body"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value[:max_chars]
    screenshot = item.get("screenshot")
    if isinstance(screenshot, str):
        text_path = screenshot.rsplit(".", 1)[0] + ".txt"
        try:
            return Path(text_path).read_text(encoding="utf-8")[:max_chars]
        except OSError:
            return ""
    return ""


def _heuristic_fallback(item: dict[str, Any], reason: str) -> dict[str, Any]:
    tag = item.get("ai_tag") or "Other"
    if tag in {"404/NOT Found", "Other", "Unknown"}:
        verdict = "likely_fp"
        confidence = 0.65
    else:
        verdict = "inconclusive"
        confidence = 0.35
    return {
        "verdict": verdict,
        "confidence": confidence,
        "reason": f"LLM unavailable; heuristic fallback used ({reason})",
        "category_corrected": tag,
        "model": "heuristic",
        "tokens_used": 0,
        "cost_usd": 0.0,
    }


def _load_manual_fp_urls(findings: list[dict[str, Any]]) -> set[str]:
    urls = sorted({item.get("url") for item in findings if item.get("url")})
    database_url = os.getenv("DATABASE_URL")
    if not urls or not database_url:
        return set()

    try:
        import psycopg
    except ImportError:
        return set()

    dsn = database_url.replace("postgresql+asyncpg://", "postgresql://").replace(
        "postgresql+psycopg://", "postgresql://"
    )
    query = """
        select f.url
        from findings f
        join lateral (
            select label
            from findings_triage
            where finding_id = f.id
            order by labeled_at desc, id desc
            limit 1
        ) latest_triage on true
        where f.url = any(%s) and latest_triage.label = 'fp'
    """
    try:
        with psycopg.connect(dsn, connect_timeout=5) as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, (urls,))
                return {row[0] for row in cursor.fetchall()}
    except Exception as exc:
        logger.warning("Unable to load manual FP overrides: %s", exc)
        return set()


def _apply_manual_fp_override(item: dict[str, Any], manual_fp_urls: set[str]) -> None:
    if item.get("url") not in manual_fp_urls:
        return
    existing = item.get("llm_validation") or {}
    item["llm_validation"] = {
        "verdict": "likely_fp",
        "confidence": 0.99,
        "reason": "Previously marked false positive by human triage for this exact URL; suppressing repeat finding by default.",
        "category_corrected": existing.get("category_corrected") or item.get("ai_tag") or "False positive",
        "model": existing.get("model", OPENAI_MODEL_VALIDATOR),
        "tokens_used": int(existing.get("tokens_used") or 0),
        "cost_usd": float(existing.get("cost_usd") or 0),
    }


def _load_examples(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    examples = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                examples.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return examples[-limit:]


def _estimate_cost(tokens: int) -> float:
    # Conservative placeholder until exact model billing is known.
    return (tokens / 1_000_000) * float(os.getenv("LLM_COST_PER_MILLION_TOKENS", "10"))

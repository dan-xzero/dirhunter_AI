from __future__ import annotations

from datetime import date, datetime
from typing import Any


def json_safe(value: Any) -> Any:
    """Convert scanner data into JSONB-safe values without losing useful context."""
    if isinstance(value, str):
        return clean_text(value)
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    return str(value)


def clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    return value.replace("\x00", "")


def body_excerpt_from_finding(finding: dict[str, Any], max_chars: int = 1500) -> str | None:
    for key in ("body_excerpt", "page_text", "text", "body"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value[:max_chars]

    screenshot = finding.get("screenshot")
    if isinstance(screenshot, str) and screenshot:
        text_path = screenshot.rsplit(".", 1)[0] + ".txt"
        try:
            with open(text_path, "r", encoding="utf-8") as handle:
                return handle.read(max_chars)
        except OSError:
            return None

    return None

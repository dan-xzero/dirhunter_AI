import json, os, math, threading
from pathlib import Path

RATE_FILE = Path("db/rate_stats.json")
RATE_FILE.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()

DEFAULT_MIN_RATE = 5
DEFAULT_MAX_RATE = 100


def _load():
    if RATE_FILE.exists():
        try:
            with RATE_FILE.open() as fp:
                return json.load(fp)
        except Exception:
            return {}
    return {}


def _save(data):
    with RATE_FILE.open("w") as fp:
        json.dump(data, fp, indent=2)


def get_rate(domain: str, default: int = 30) -> int:
    """Return the current suggested rate for a domain."""
    with _lock:
        data = _load()
        return data.get(domain, {}).get("rate", default)


def update_stats(domain: str, total_requests: int, num_429: int):
    """Update moving stats for domain and adjust rate if necessary."""
    if total_requests == 0:
        return

    ratio = num_429 / total_requests
    with _lock:
        data = _load()
        entry = data.setdefault(domain, {"rate": 30, "history": []})

        # keep last 10 records
        hist = entry["history"]
        hist.append({"ratio": ratio, "total": total_requests, "rl": num_429})
        if len(hist) > 10:
            hist.pop(0)

        rate = entry["rate"]

        # Decision logic
        if ratio > 0.05 and rate > DEFAULT_MIN_RATE:
            rate = max(DEFAULT_MIN_RATE, math.floor(rate / 2))
        else:
            # look at last two history points
            if len(hist) >= 2 and all(h["ratio"] < 0.01 for h in hist[-2:]):
                if rate < DEFAULT_MAX_RATE:
                    rate = min(DEFAULT_MAX_RATE, math.ceil(rate * 1.5))

        entry["rate"] = rate
        _save(data)

    return rate 
import os, json, time, threading, requests
from pathlib import Path

VT_API_KEY = os.getenv("VT_API_KEY")
CACHE_FILE = Path("db/vt_cache.json")
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()
CACHE_TTL = 60 * 60 * 24 * 7  # 7 days


def _load_cache():
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_cache(data):
    CACHE_FILE.write_text(json.dumps(data, indent=2))


def query_hash(sha1: str):
    """Return dict {positives,total} using VT v3 API, with cache."""
    if not VT_API_KEY:
        return None  # VT disabled

    with _lock:
        cache = _load_cache()
        entry = cache.get(sha1)
        now = int(time.time())
        if entry and now - entry.get("ts", 0) < CACHE_TTL:
            return entry["result"]

    # Not cached or expired
    url = f"https://www.virustotal.com/api/v3/files/{sha1}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) or 0
            result = {"positives": positives, "total": total}
        elif r.status_code == 404:
            result = {"positives": 0, "total": 0}
        else:
            # Some API error; don't cache
            return None
    except Exception:
        return None

    with _lock:
        cache = _load_cache()
        cache[sha1] = {"result": result, "ts": int(time.time())}
        _save_cache(cache)

    return result 
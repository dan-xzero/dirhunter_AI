import json, threading
from pathlib import Path
from datetime import datetime
from typing import Optional


PROGRESS_FILE = Path("db/ffuf_progress.json")
PROGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()


def _load():
    if PROGRESS_FILE.exists():
        try:
            with PROGRESS_FILE.open() as fp:
                return json.load(fp)
        except Exception:
            pass
    return {}


def _save(data):
    with PROGRESS_FILE.open("w") as fp:
        json.dump(data, fp, indent=2)


def get_last_position(domain: str, wordlist: str) -> Optional[int]:
    """Return last processed wordlist index for domain+wordlist or None."""
    key = f"{domain}|{wordlist}"
    with _lock:
        data = _load()
        return data.get(key, {}).get("last_pos")


def update_position(domain: str, wordlist: str, pos: int):
    key = f"{domain}|{wordlist}"
    with _lock:
        data = _load()
        entry = data.setdefault(key, {})
        if entry.get("last_pos", -1) < pos:
            entry["last_pos"] = pos
            entry["updated"] = datetime.utcnow().isoformat()
            _save(data) 
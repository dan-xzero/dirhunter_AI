import os, time, shutil, logging
from pathlib import Path
from typing import List
from config import SCREENSHOT_DIR, RAW_RESULTS_DIR, CLEANUP_DAYS

logger = logging.getLogger(__name__)


def _age_in_days(path: Path) -> float:
    try:
        mtime = path.stat().st_mtime
    except Exception:
        return 0.0
    return (time.time() - mtime) / 86400.0


def _delete_path(p: Path):
    try:
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
        logger.info(f"[cleanup] Removed old path: {p}")
    except Exception as e:
        logger.warning(f"[cleanup] Failed to delete {p}: {e}")


def cleanup_old_runs(retention_days: int = CLEANUP_DAYS):
    """Delete screenshot/raw result items older than retention_days."""
    for base in [SCREENSHOT_DIR, RAW_RESULTS_DIR]:
        base_path = Path(base)
        if not base_path.exists():
            continue
        for item in base_path.iterdir():
            # Determine age – if directory, use latest mtime among contents
            age_days = _age_in_days(item)
            if age_days >= retention_days:
                _delete_path(item) 
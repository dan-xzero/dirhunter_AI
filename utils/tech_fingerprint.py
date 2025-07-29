# utils/tech_fingerprint.py – now a wrapper around simple_tech_detector
import json, time, os
from pathlib import Path
from typing import Any, Dict, Optional
import urllib.parse
import logging

# Configure logging
logger = logging.getLogger(__name__)

RAW_DIR = Path("results/tech_detection_raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)
CACHE_FILE = Path("db/tech_cache.json")
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
TTL = 60 * 60 * 24  # 24 h


def _load_cache() -> Dict[str, Any]:
    try:
        return json.loads(CACHE_FILE.read_text()) if CACHE_FILE.exists() else {}
    except Exception:
        return {}


def _save_cache(data: Dict[str, Any]):
    CACHE_FILE.write_text(json.dumps(data, indent=2))


def _slug(url: str) -> str:
    p = urllib.parse.urlparse(url)
    return (p.netloc or p.path).replace(":", "_").replace("/", "_")


def fingerprint(url: str, _headers: str = "", _body: str = "") -> Optional[Dict[str, Any]]:
    """Return technology dict for the given URL or None."""
    cache = _load_cache()
    entry = cache.get(url)
    if entry and time.time() - entry.get("ts", 0) < TTL:
        return entry.get("tech")

    # Import simple_tech_detector here to avoid circular imports
    try:
        from utils.simple_tech_detector import detect_technologies
        
        logger.info(f"Using browser-free detector for {url}")
        start_time = time.time()
        tech = detect_technologies(url)
        elapsed = time.time() - start_time
        
        if tech is not None:
            logger.info(f"Browser-free detector completed for {url} in {elapsed:.2f}s")
            
            # Save raw results
            RAW_DIR.joinpath(f"{_slug(url)}.json").write_text(json.dumps(tech, indent=2))
            
            # Update cache
            cache[url] = {"tech": tech, "ts": time.time()}
            _save_cache(cache)
            
            return tech
        else:
            logger.warning(f"No technologies detected for {url}")
            return None
            
    except ImportError:
        logger.error("simple_tech_detector module not available")
        return None
    except Exception as e:
        logger.error(f"Error detecting technologies: {e}")
        return None 
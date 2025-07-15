# utils/tech_fingerprint.py – minimal CLI-only fingerprinting using Wappalyzer JSON output
import json, subprocess, time, os, sys, urllib.parse, tempfile
from pathlib import Path
from typing import Any, Dict, Optional
import re as _re

RAW_DIR = Path("results/wappalyzer_raw")
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


def _run_cli(url: str) -> Optional[Dict[str, Any]]:
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    tmp.close()
    cmd = ["wappalyzer", "-i", url, "-oJ", tmp.name]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=30)
    except FileNotFoundError:
        # Fallback to module execution (pip install wappalyzer installs entry-point here)
        cmd = [sys.executable, "-m", "wappalyzer.cli", "-i", url, "-oJ", tmp.name]
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=30)
    except Exception:
        return None

    try:
        data = json.loads(Path(tmp.name).read_text())
    finally:
        os.unlink(tmp.name)
    techs = data.get(url) or next(iter(data.values()), None)
    if techs is None:
        return None

    RAW_DIR.joinpath(f"{_slug(url)}.json").write_text(json.dumps(techs, indent=2))
    return techs


def fingerprint(url: str, _headers: str = "", _body: str = "") -> Optional[Dict[str, Any]]:
    """Return Wappalyzer tech dict for the given URL or None."""
    cache = _load_cache()
    entry = cache.get(url)
    if entry and time.time() - entry.get("ts", 0) < TTL:
        return entry.get("tech")

    tech = _run_cli(url)
    if tech is not None:
        # Build component list for CVE lookup (name + version if present)
        comps = []
        for name, info in tech.items():
            ver = info.get("version") if isinstance(info, dict) else None
            if not ver:
                continue

            # --- normalize package name for OSV ---
            n = name.lower().strip()
            n = _re.sub(r"[\. ]js$", "", n)  # remove .js or js suffix
            n = n.replace(" ", "-")           # spaces to dashes (e.g., react dom)

            # explicit mapping overrides
            explicit = {
                "next.js": "next",
                "nextjs": "next",
                "react": "react",
                "react-dom": "react-dom",
            }
            n = explicit.get(n, n)

            comps.append({"name": n, "version": ver})

        if comps:
            try:
                from utils.cve import check_components
                cve_res = check_components(comps)
                if cve_res.get("total_vulns"):
                    tech["cve_vulns"] = cve_res["total_vulns"]
                    tech["cve_details"] = cve_res["details"]
            except Exception:
                pass

        cache[url] = {"tech": tech, "ts": time.time()}
        _save_cache(cache)
    return tech 
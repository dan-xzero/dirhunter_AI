import json, time, threading, requests
from pathlib import Path
from typing import Dict, List, Any, Optional

CACHE_FILE = Path("db/cve_cache.json")
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()
TTL = 60 * 60 * 24  # 24h


def _load() -> Dict[str, Any]:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save(data: Dict[str, Any]):
    CACHE_FILE.write_text(json.dumps(data, indent=2))


def _query_osv(packages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Return list of OSV vulnerabilities for given packages list."""
    url = "https://api.osv.dev/v1/querybatch"
    payload = {"queries": [{"package": pkg} for pkg in packages]}
    try:
        r = requests.post(url, json=payload, timeout=8)
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception:
        return []

# ─────────── NEW: generic tech version CVE check ───────────

_ECOSYSTEM_DEFAULTS = {
    "js": "npm",
    "javascript": "npm",
    "node": "npm",
    "python": "PyPI",
    "py": "PyPI",
    "ruby": "RubyGems",
    "rust": "crates.io",
    "go": "Go",
    "java": "Maven",
}


def _infer_ecosystem(name: str) -> str:
    """Very naive mapping of package/tech name to OSV ecosystem."""
    n = name.lower()
    for key, eco in _ECOSYSTEM_DEFAULTS.items():
        if key in n:
            return eco
    # default to npm because many web libs are JS
    return "npm"


def check_components(components: List[Dict[str, str]]) -> Dict[str, Any]:
    """Given list of {name, version[, ecosystem]} return aggregated vuln info."""
    if not components:
        return {}

    # Prepare queries and cache key
    queries = []
    for comp in components:
        name = comp.get("name")
        version = comp.get("version")
        # Skip entries with invalid names
        if not name or not version or name.lower() in {"null", "none"}:
            continue
        eco = comp.get("ecosystem") or _infer_ecosystem(name)
        queries.append({"name": name, "version": version, "ecosystem": eco})

    if not queries:
        return {}

    key = json.dumps(sorted(queries, key=lambda x: (x["ecosystem"], x["name"])) , sort_keys=True)
    with _lock:
        cache = _load()
        entry = cache.get(key)
        if entry and time.time() - entry["ts"] < TTL:
            return entry["result"]

    osv_results = _query_osv(queries)
    vuln_count = 0
    vuln_details: Dict[str, Dict[str, Any]] = {}

    # Results are in the same order as queries. Pair them so we always know the
    # originating package name even if the OSV payload omits it.
    for query, res in zip(queries, osv_results):
        vulns = res.get("vulns", [])
        if not vulns:
            continue
        pkg_name = query["name"]
        vuln_details[pkg_name] = {
            "version": query["version"],
            "ids": [v.get("id") for v in vulns],
        }
        vuln_count += len(vulns)

    result = {"total_vulns": vuln_count, "details": vuln_details}
    with _lock:
        cache[key] = {"result": result, "ts": time.time()}
        _save(cache)
    return result


def check_node_manifest(pkg_json: str) -> Dict[str, Any]:
    """Given package.json content return vulnerability summary."""
    try:
        data = json.loads(pkg_json)
    except Exception:
        return {}

    deps = data.get("dependencies", {}) | data.get("devDependencies", {})
    queries = []
    for name, version in deps.items():
        # Strip ^ ~ etc.
        ver = version.lstrip("^~>=<")
        queries.append({"name": name, "version": ver, "ecosystem": "npm"})

    key = json.dumps(queries, sort_keys=True)
    with _lock:
        cache = _load()
        entry = cache.get(key)
        if entry and time.time() - entry["ts"] < TTL:
            return entry["result"]

    osv_results = _query_osv(queries)
    vuln_count = 0
    vuln_details: Dict[str, Dict[str, Any]] = {}
    for query, res in zip(queries, osv_results):
        vulns = res.get("vulns", [])
        if not vulns:
            continue
        pkg_name = query["name"]
        vuln_details[pkg_name] = {
            "version": query["version"],
            "ids": [v.get("id") for v in vulns],
        }
        vuln_count += len(vulns)

    result = {"total_vulns": vuln_count, "details": vuln_details}
    with _lock:
        cache[key] = {"result": result, "ts": time.time()}
        _save(cache)
    return result 
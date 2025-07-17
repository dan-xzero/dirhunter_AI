# File: dirhunter_ai/utils/filters.py

import subprocess, os, hashlib, datetime, requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.db_handler import init_db, get_stored_hash, update_hash_record, track_finding, get_finding_status
import re, urllib.parse
import json

# ssdeep may not be installed in all environments; fallback gracefully
try:
    import ssdeep  # type: ignore
except Exception:  # pragma: no cover
    class _SSDeepFallback:  # pylint: disable=too-few-public-methods
        @staticmethod
        def hash(data: str) -> str:
            return ""  # no fuzzy hash

        @staticmethod
        def compare(a: str, b: str) -> int:
            return 0

    ssdeep = _SSDeepFallback()

# ─────────── CONFIG ───────────
SOFT_404_PHRASES = [
    "oops, you must be lost", "page not found", "go to homepage",
    "404 error", "not exist", "return to homepage"
]
EXCLUDE_PATTERNS = ["/healthz", "/status"]
DOMAIN_OVERRIDES = {}

# ─────────── LOGGING SETUP ───────────
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
SKIPPED_FILE = os.path.join(LOG_DIR, f"skipped_{timestamp}.txt")
KEPT_FILE = os.path.join(LOG_DIR, f"kept_{timestamp}.txt")
SUMMARY_FILE = os.path.join(LOG_DIR, f"summary_{timestamp}.txt")

curl_cache = {}  # url → (is_soft404, sha1_hash, fuzzy_hash, final_status, is_downloadable)
init_db()

# ─────────── LOG HELPERS ───────────
def log_skipped_endpoint(url: str, reason: str = "unknown"):
    entry = f"[{reason}] {url}"
    with open(SKIPPED_FILE, "a") as f:
        f.write(entry + "\n")

def log_kept_endpoint(url: str):
    with open(KEPT_FILE, "a") as f:
        f.write(url + "\n")

def log_summary(domain, raw_count, after_heuristic, after_cluster, new_count, changed_count, existing_count):
    with open(SUMMARY_FILE, "a") as f:
        f.write(f"Domain: {domain}\n")
        f.write(f"Raw results: {raw_count}\n")
        f.write(f"After heuristic: {after_heuristic}\n")
        f.write(f"After cluster: {after_cluster}\n")
        f.write(f"  - New findings: {new_count}\n")
        f.write(f"  - Changed findings: {changed_count}\n")
        f.write(f"  - Existing findings: {existing_count}\n\n")

# ─────────── CURL FETCHER ───────────
HEADERS = {
    "User-Agent": "Mozilla/5.0 (DirHunter AI)"
}


def curl_fetch_hash(url: str):
    """Fetch content using requests (follows redirects) and return soft-404 flag, hashes, final status, and whether it's a direct download."""
    # Return cached value if present
    if url in curl_cache:
        val = curl_cache[url]
        if len(val) < 8:
            val = val + (None,) * (8 - len(val))
            curl_cache[url] = val
        return val

    try:
        resp = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        final_status = resp.status_code

        # Read at most 2 MB to avoid huge memory – larger bodies will be truncated for hashing
        max_bytes = 2 * 1024 * 1024
        body_bytes = resp.content[:max_bytes]

        # Soft-404 heuristic
        body_sample = body_bytes[:10000].decode("utf-8", errors="ignore").lower()
        is_soft404 = final_status in (404, 410) or any(kw in body_sample for kw in SOFT_404_PHRASES)

        # Hashes
        body_hash = hashlib.sha1(body_bytes).hexdigest() if body_bytes else None
        try:
            fuzzy_hash = ssdeep.hash(body_bytes.decode('latin-1', errors='ignore')) if body_bytes else ""
        except Exception:
            fuzzy_hash = ""

        # Determine downloadability
        ctype = resp.headers.get("Content-Type", "").lower()
        is_download = (
            (ctype and not ctype.startswith("text") and "html" not in ctype) or
            len(body_bytes) > 250000  # >250 KB
        )

        download_meta = None
        if is_download:
            try:
                download_meta = inspect_download(body_bytes, ctype)
            except Exception:
                download_meta = None

        # Tech fingerprinting (safe for text / small bodies)
        tech = None
        if len(body_bytes) < 500_000:  # Only analyse reasonably small pages
            try:
                from utils.tech_fingerprint import fingerprint as _tfp
                hdr_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                body_text = body_bytes.decode("utf-8", errors="ignore")
                tech = _tfp(url, hdr_str, body_text)

                # ⟶ CVE look-up for detected tech versions
                if tech and (tech.get("version") or tech.get("wapp")):
                    from utils.cve import check_components
                    comps = []
                    if tech.get("name") and tech.get("version"):
                        comps.append({"name": tech["name"], "version": tech["version"]})
                    if tech.get("wapp"):
                        for n, vers in tech["wapp"].items():
                            if isinstance(vers, (list, tuple)):
                                v = vers[0] if vers else None
                            else:
                                v = vers
                            if v:
                                comps.append({"name": n, "version": v})
                    cve_res = check_components(comps)
                    if cve_res.get("total_vulns"):
                        tech["cve_vulns"] = cve_res["total_vulns"]
                        tech["cve_details"] = cve_res["details"]
            except Exception:
                tech = None

        # VirusTotal look-up could be added here (skipped for performance)
        vt_result = None

        val = (is_soft404, body_hash, fuzzy_hash, final_status, is_download, download_meta, vt_result, tech)
    except Exception:
        val = (False, None, None, None, False, None, None, None)

    # Ensure 8-tuple length and cache
    if len(val) < 8:
        val = val + (None,) * (8 - len(val))
    curl_cache[url] = val
    return val

# ─────────── PARALLEL CURL RUNNER ───────────
def parallel_curl_fetch(urls, max_workers=10):
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(curl_fetch_hash, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                results[url] = result
            except Exception:
                results[url] = (False, None, None, None, False)
    return results

# ─────────── MAIN FILTER ───────────
def filter_false_positives(domain, results, ignore_hash=False):
    print(f"[~] Filtering for {domain} – raw: {len(results)}")

    # Step 1: heuristic filtering (length + pattern)
    freq = {}
    for r in results:
        freq[r["length"]] = freq.get(r["length"], 0) + 1
    common_len = max(freq.keys(), key=lambda k: freq[k]) if freq else None

    base_kw = {"admin", "login", "dashboard", "config", "debug", "upload", "backup"}
    kw_set = base_kw | set(DOMAIN_OVERRIDES.get(domain.lower(), {}).get("keywords", []))

    stage1 = []
    for r in results:
        url, status, length = r["url"].lower(), r["status"], r["length"]

        if any(pat in url for pat in EXCLUDE_PATTERNS):
            log_skipped_endpoint(r["url"], reason="pattern-skip")
            continue

        kw_hit = any(k in url for k in kw_set)
        short_rd = status in (301, 302) and length == 0 and "." not in r["path"].split("/")[-1]

        keep = status in (200, 301, 302) and (length != common_len or kw_hit or short_rd)
        if keep:
            stage1.append(r)
        else:
            log_skipped_endpoint(r["url"], reason="length-filter")

    print(f"[~] After heuristic pass: {len(stage1)} kept / {len(results)-len(stage1)} skipped")

    # Step 2: curl + hash + cluster
    urls_to_check = [r["url"] for r in stage1]
    curl_results = parallel_curl_fetch(urls_to_check, max_workers=10)

    clusters = defaultdict(list)
    for r in stage1:
        is_soft, body_hash, fuzzy_hash, final_status, is_downloadable, download_meta, vt_result, tech = curl_results.get(r["url"], (False, None, None, None, False, None, None, None))
        r["vt"] = vt_result
        r["download_meta"] = download_meta
        r["tech"] = tech
        # Update status to final status if available
        if final_status:
            r["status_initial"] = r["status"]  # keep original
            r["status"] = final_status
        r["final_status"] = r.get("status")
        r["downloadable"] = is_downloadable
        r["body_hash"] = body_hash
        r["fuzzy_hash"] = fuzzy_hash
        r["sha1_hash"] = body_hash  # Add for compatibility
        clusters[(r["status"], r["length"], body_hash)].append(r)

    final = []
    seen_fuzzy = []
    
    # Track counts by status
    new_count = 0
    changed_count = 0
    existing_count = 0

    for key, items in clusters.items():
        probe = items[0]
        is_soft, _, _, _, _, _, _, _ = curl_results.get(probe["url"], (False, None, None, None, False, None, None, None))

        if is_soft:
            for itm in items:
                log_skipped_endpoint(itm["url"], reason="curl-soft404")
            print(f"[~] Cluster {key} soft-404 → {len(items)} skipped")
        else:
            for itm in items:
                # Fuzzy duplicate check (handle missing fuzzy_hash safely)
                fuzzy = itm.get("fuzzy_hash") or ""
                is_dup = False
                if fuzzy:
                    for seen in seen_fuzzy:
                        if seen and ssdeep.compare(fuzzy, seen) > 90:
                            is_dup = True
                            break
                if is_dup:
                    log_skipped_endpoint(itm["url"], reason="fuzzy-dupe")
                    continue
                seen_fuzzy.append(fuzzy)

                # Assign AI tag early for downloadable files
                if itm.get("downloadable"):
                    itm["ai_tag"] = "Downloadable File"

                # Track finding in database first
                itm["domain"] = domain
                track_finding(itm)
                
                # Get finding status AFTER tracking (pass hash for exact match)
                finding_status = get_finding_status(itm["url"], itm["sha1_hash"])
                itm["finding_status"] = finding_status['status']
                itm["times_seen"] = finding_status['times_seen']
                itm["first_seen"] = finding_status.get('first_seen')
                
                # Count by status
                if finding_status['status'] == 'new':
                    new_count += 1
                elif finding_status['status'] == 'changed':
                    changed_count += 1
                else:
                    existing_count += 1

                # Include all findings, even existing/unchanged ones, so they appear in reports
                final.append(itm)
                log_kept_endpoint(itm["url"])
                update_hash_record(itm["url"], itm["body_hash"])

                # Skip forbidden pages (often false positives)
                if itm.get("status") == 403:
                    log_skipped_endpoint(itm["url"], reason="status-403")
                    continue

    print(f"[+] Final count for {domain}: {len(final)} (new: {new_count}, changed: {changed_count}, existing: {existing_count})")
    log_summary(domain, raw_count=len(results), after_heuristic=len(stage1), 
                after_cluster=len(final), new_count=new_count, 
                changed_count=changed_count, existing_count=existing_count)
    return final


CLIENT_REDIRECT_RE = re.compile(r"<meta[^>]+http-equiv=\"?refresh\"?[^>]+content=\"?\s*\d+\s*;\s*url=([^\"'>]+)\"?", re.IGNORECASE)
JS_LOCATION_RE    = re.compile(r"location\.href\s*=\s*[\'\"]([^\'\"]+)[\'\"]", re.IGNORECASE)


def _extract_client_redirect(base_url: str, body: str):
    """Return absolute redirect URL if meta/js redirect detected, else None"""
    match = CLIENT_REDIRECT_RE.search(body)
    if not match:
        match = JS_LOCATION_RE.search(body)
    if match:
        target = match.group(1).strip()
        # Resolve relative URL
        return urllib.parse.urljoin(base_url, target)
    return None

# ─────────── DOWNLOAD INSPECTION ───────────

INSPECT_SIZE_LIMIT = 5 * 1024 * 1024  # 5 MB
SECRET_PATTERNS = [re.compile(p, re.I) for p in [
    r"api[_-]?key", r"secret", r"password", r"token", r"access[_-]?key", r"aws[_-]?secret", r"-----BEGIN RSA",
]]


def inspect_download(body_bytes: bytes, content_type: str):
    """Return simple metadata dict for small binary/text downloads."""
    meta = {}
    size = len(body_bytes)
    meta["size"] = size
    meta["content_type"] = content_type

    if size > INSPECT_SIZE_LIMIT:
        meta["note"] = "Skipped (too large)"
        return meta

    # ZIP file
    if body_bytes[:4] == b"PK\x03\x04":
        import io, zipfile
        try:
            with zipfile.ZipFile(io.BytesIO(body_bytes)) as zf:
                meta["archive_filenames"] = zf.namelist()[:20]
                meta["note"] = "zip-list"
        except Exception as e:
            meta["error"] = str(e)

    # GZIP (could be tar.gz)
    elif body_bytes[:2] == b"\x1f\x8b":
        meta["note"] = "gzip"

    # Textual content we can decode
    else:
        try:
            text = body_bytes.decode("utf-8", errors="ignore")
            found = []
            for pat in SECRET_PATTERNS:
                if pat.search(text):
                    found.append(pat.pattern)
            if found:
                meta["potential_secrets"] = list(set(found))
            # Check for package.json dependencies
            if '"dependencies"' in text and text.strip().startswith('{'):
                try:
                    pkg_json = json.loads(text)
                    deps = pkg_json.get('dependencies', {})
                    from utils.cve import check_node_manifest
                    cve_info = check_node_manifest(text)
                    if cve_info and cve_info.get("total_vulns"):
                        meta["cve_vulns"] = cve_info["total_vulns"]
                        meta["cve_details"] = cve_info["details"]
                except Exception:
                    pass
        except Exception:
            pass

    return meta

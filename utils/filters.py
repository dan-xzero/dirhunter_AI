# File: dirhunter_ai/utils/filters.py

import subprocess, os, hashlib, datetime, requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.db_handler import init_db, get_stored_hash, update_hash_record, track_finding, get_finding_status
import re, urllib.parse
import json
from typing import List

# Import technology detection with fallback
try:
    from utils.fingerprint_manager import detect_technologies_for_url as detect_technology
except ImportError:
    # Fallback to direct import if manager is not available
    try:
        from utils.tech_fingerprint import fingerprint as detect_technology
    except ImportError:
        detect_technology = None

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
    "404 error", "not exist", "return to homepage",
    # E-commerce specific
    "product not found", "item not found", "shop not found",
    "store not found", "collection not found", "category not found",
    # Shopify specific
    "continue shopping", "search our store", "popular collections",
    "404 not found", "the page you requested does not exist",
    # General CMS
    "nothing found", "no results found", "content not found",
    "article not found", "post not found", "sorry, we couldn't find",
    "the page you are looking for", "page cannot be found",
    "page does not exist", "page is not available",
    # Common redirect messages
    "you will be redirected", "redirecting to", "please wait"
]
def get_exclude_patterns(domain: str = "") -> List[str]:
    """
    Get dynamic exclude patterns based on domain characteristics
    
    Args:
        domain: The target domain to customize patterns for
        
    Returns:
        List of regex patterns to exclude
    """
    base_patterns = ["/healthz", "/status"]
    
    # Add API patterns only if we detect API-heavy domains
    # This could be enhanced with domain-specific logic
    api_patterns = [
        r"/api/.*/health$",
        r"/api/.*/status$",
        r"/api/.*/ping$",
        r"/api/.*/healthz$",
        r"/api/.*/ready$",
        r"/api/.*/live$"
    ]
    
    # For now, include API patterns by default, but this could be made smarter
    # based on initial scan results or domain characteristics
    return base_patterns + api_patterns

# Default patterns for backward compatibility
EXCLUDE_PATTERNS = get_exclude_patterns()
DOMAIN_OVERRIDES = {}

# Download detection config
DOWNLOAD_SIZE_THRESHOLD = 1048576  # 1MB instead of 250KB
DOWNLOAD_CONTENT_TYPES = [
    "application/octet-stream", "application/zip", "application/pdf",
    "application/x-tar", "application/x-gzip", "application/x-bzip2",
    "application/java-archive", "application/x-rar-compressed",
    "image/", "video/", "audio/", "font/", "application/vnd",
    "application/x-shockwave-flash", "application/x-msdownload"
]

# Enhanced download detection patterns
WELL_KNOWN_DOWNLOAD_PATTERNS = [
    "apple-app-site-association",
    "assetlinks.json",
    "security.txt",
    "robots.txt",
    "sitemap.xml",
    "manifest.json",
    "service-worker.js",
    "sw.js"
]

DOWNLOADABLE_EXTENSIONS = [
    ".json", ".xml", ".txt", ".csv", ".yaml", ".yml", 
    ".js", ".css", ".pdf", ".zip", ".tar.gz", ".rar"
]

def is_json_content(content_bytes):
    """Detect if content is JSON regardless of content-type"""
    try:
        content = content_bytes.decode('utf-8', errors='ignore').strip()
        return content.startswith('{') and content.endswith('}') and '"' in content
    except:
        return False

def is_xml_content(content_bytes):
    """Detect if content is XML regardless of content-type"""
    try:
        content = content_bytes.decode('utf-8', errors='ignore').strip()
        return content.startswith('<?xml') or (content.startswith('<') and content.endswith('>'))
    except:
        return False

def has_downloadable_extension(url):
    """Check if URL has a downloadable file extension"""
    return any(url.lower().endswith(ext) for ext in DOWNLOADABLE_EXTENSIONS)

def is_well_known_config(url):
    """Check if URL is a well-known configuration file"""
    return any(pattern in url.lower() for pattern in WELL_KNOWN_DOWNLOAD_PATTERNS)

def detect_content_mismatch(content_type, content_bytes):
    """Detect when content-type doesn't match actual content"""
    if not content_type:
        return False
    
    # JSON served with wrong content-type
    if content_type == "application/x-www-form-urlencoded" and is_json_content(content_bytes):
        return True
    
    # XML served with wrong content-type  
    if content_type == "text/plain" and is_xml_content(content_bytes):
        return True
    
    # JSON served as text/plain
    if content_type == "text/plain" and is_json_content(content_bytes):
        return True
    
    return False

# ─────────── LOGGING SETUP ───────────
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
SKIPPED_FILE = os.path.join(LOG_DIR, f"skipped_{timestamp}.txt")
KEPT_FILE = os.path.join(LOG_DIR, f"kept_{timestamp}.txt")
SUMMARY_FILE = os.path.join(LOG_DIR, f"summary_{timestamp}.txt")

curl_cache = {}  # url → (is_soft404, sha1_hash, fuzzy_hash, final_status, is_downloadable)
catch_all_domains = {}  # domain → (is_catch_all, common_hash, common_size)
unresolved_domains = set()  # Domains that failed DNS resolution – skip further fetch attempts
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

# ─────────── CATCH-ALL DETECTION ───────────
def detect_catch_all_page(domain: str) -> tuple:
    """Pre-scan to detect if domain has a catch-all page for 404s"""
    import random
    import string
    
    # Generate 3 random non-existent paths
    random_paths = []
    for _ in range(3):
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        random_paths.append(f"/{random_str}")
    
    responses = []
    for path in random_paths:
        url = f"{domain.rstrip('/')}{path}"
        try:
            import warnings
            from urllib3.exceptions import InsecureRequestWarning
            resp = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True, verify=True)
            
            # Only check first 50KB for performance
            content = resp.content[:51200]
            content_hash = hashlib.sha1(content).hexdigest()
            try:
                fuzzy = ssdeep.hash(content.decode("latin-1", errors="ignore"))
            except Exception:
                fuzzy = ""
            responses.append({
                'status': resp.status_code,
                'size': len(resp.content),
                'hash': content_hash,
                'url': resp.url,
                'fuzzy': fuzzy
            })
        except Exception as e:
            import logging
            # Check if it's a DNS resolution error
            error_str = str(e).lower()
            if 'failed to resolve' in error_str or 'nodename nor servname provided' in error_str:
                logging.warning(f"[catch-all] DNS resolution failed for {domain}")
                # Return early - domain doesn't exist
                return (False, None, None)
            logging.debug(f"[catch-all] Error checking {url}: {e}")
            continue
    
    if len(responses) < 2:
        return (False, None, None)
    
    # Check if all responses have same hash or size
    hashes = [r['hash'] for r in responses]
    sizes  = [r['size'] for r in responses]
    fuzzes = [r['fuzzy'] for r in responses if r.get('fuzzy')]
    
    # If all hashes are identical, it's a catch-all
    if len(set(hashes)) == 1:
        return (True, hashes[0], sizes[0])
    
    # If all sizes are identical and > 10KB, likely catch-all
    if len(set(sizes)) == 1 and sizes[0] > 10240:
        return (True, None, sizes[0])

    # NEW: if all responses are >90% similar by ssdeep treat as catch-all
    if len(fuzzes) >= 2:
        sim_scores = []
        base = fuzzes[0]
        for fz in fuzzes[1:]:
            try:
                sim_scores.append(ssdeep.compare(base, fz))
            except Exception:
                pass
        if sim_scores and min(sim_scores) >= 90:
            return (True, None, None)
    
    return (False, None, None)

# ─────────── CURL FETCHER ───────────
# Headers will be generated dynamically by user_agent_manager
HEADERS = None  # Will be set dynamically


def curl_fetch_hash(url: str):
    """Fetch content using requests (follows redirects) and return soft-404 flag, hashes, final status, and whether it's a direct download."""
    import urllib.parse as _urlparse
    domain = _urlparse.urlparse(url).netloc

    # Fast-path: previously marked as unresolved → treat as soft-404 immediately
    if domain in unresolved_domains:
        return (True, None, None, None, False, None, None, None)

    # Return cached value if present
    if url in curl_cache:
        val = curl_cache[url]
        if len(val) < 8:
            val = val + (None,) * (8 - len(val))
            curl_cache[url] = val
        return val

    try:
        import warnings
        from urllib3.exceptions import InsecureRequestWarning
        from utils.user_agent_manager import get_realistic_headers
        
        # Get dynamic headers
        if HEADERS is None:
            headers = get_realistic_headers(include_scanner_header=True)
        else:
            headers = HEADERS
            
        # Ignore TLS cert errors so we can still inspect bodies with bad/hostname-mismatch certs
        resp = requests.get(url, headers=headers, timeout=15, allow_redirects=True, verify=True)
        final_status = resp.status_code

        # Memory optimization: For HTML, only read what we need
        ctype = resp.headers.get("Content-Type", "").lower()
        is_html = "html" in ctype or ctype.startswith("text/")
        
        if is_html and len(resp.content) > 51200:  # 50KB
            # For large HTML, only read first 50KB for analysis
            body_bytes = resp.content[:51200]
            full_size = len(resp.content)
        else:
            body_bytes = resp.content
            full_size = len(body_bytes)

        # Soft-404 heuristic – check more content for large pages
        check_size = min(51200, len(body_bytes))  # Check up to 50KB
        body_sample = body_bytes[:check_size].decode("utf-8", errors="ignore").lower()
        is_soft404 = final_status in (404, 410, 403) or any(kw in body_sample for kw in SOFT_404_PHRASES)

        # ️⟵ NEW: meta/JS client redirects to login/auth pages
        try:
            redir_target = _extract_client_redirect(resp.url, body_sample)
            if redir_target and any(pat in redir_target.lower() for pat in ("/login", "/auth", "/signin")):
                is_soft404 = True
        except Exception:
            pass

        # Extra rule: many CMSes/routers issue a 301/302 to the site root ("/")
        # for unknown paths and then serve the homepage. This still yields a
        # 200 but is effectively a soft-404.  Treat that as such when:
        #   • the original path is non-empty (i.e. not just "/")
        #   • the final resolved path is the root ("/" or "")
        try:
            orig_path = urllib.parse.urlparse(url).path.rstrip("/")
            final_path = urllib.parse.urlparse(resp.url).path.rstrip("/")
            if orig_path and not final_path:
                is_soft404 = True
        except Exception:
            # Parsing issues shouldn’t break the pipeline – ignore.
            pass

        # Hashes
        body_hash = hashlib.sha1(body_bytes).hexdigest() if body_bytes else None
        try:
            fuzzy_hash = ssdeep.hash(body_bytes.decode('latin-1', errors='ignore')) if body_bytes else ""
        except Exception:
            fuzzy_hash = ""
        
        # Check against known catch-all pages
        domain = urllib.parse.urlparse(url).netloc
        if domain in catch_all_domains:
            is_catch_all, catch_all_hash, catch_all_size = catch_all_domains[domain]
            if is_catch_all and (body_hash == catch_all_hash or full_size == catch_all_size):
                is_soft404 = True

        # Enhanced downloadability detection
        import logging
        # ctype already defined above
        is_json = ctype and "json" in ctype
        
        # Enhanced download detection
        is_download_type = any(ct in ctype for ct in DOWNLOAD_CONTENT_TYPES)
        is_content_mismatch = detect_content_mismatch(ctype, body_bytes)
        is_well_known = is_well_known_config(url)
        has_download_ext = has_downloadable_extension(url)
        
        # Enhanced download logic
        is_download = (
            is_download_type or
            is_content_mismatch or
            is_well_known or
            has_download_ext or
            (ctype and not ctype.startswith("text") and "html" not in ctype and not is_json and full_size > DOWNLOAD_SIZE_THRESHOLD)
        )

        if is_download:
            reason = []
            if is_download_type:
                reason.append("content-type")
            if is_content_mismatch:
                reason.append("content-mismatch")
            if is_well_known:
                reason.append("well-known-config")
            if has_download_ext:
                reason.append("file-extension")
            logging.info("[download] Detected potential downloadable: %s (ctype=%s, size=%d, reasons: %s)", 
                        url, ctype, full_size, ", ".join(reason))

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
                if detect_technology:
                    tech = detect_technology(url)
                else:
                    tech = None


            except Exception:
                tech = None

        # VirusTotal look-up could be added here (skipped for performance)
        vt_result = None

        val = (is_soft404, body_hash, fuzzy_hash, final_status, is_download, download_meta, vt_result, tech)
    except Exception as e:
        import logging
        logging.warning("[curl_fetch] Error fetching %s: %s", url, e)

        # If this was a DNS failure, cache domain to avoid spamming further
        err_lower = str(e).lower()
        if "failed to resolve" in err_lower or "name resolution" in err_lower or "nodename nor servname" in err_lower:
            unresolved_domains.add(domain)
        # Mark network/DNS errors as soft-404 so downstream logic filters them out
        val = (True, None, None, None, False, None, None, None)

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
            except Exception as e:
                import logging
                logging.warning("[parallel_curl] Error processing %s: %s", url, e)
                results[url] = (False, None, None, None, False, None, None, None)
    return results

# ─────────── MAIN FILTER ───────────
def filter_false_positives(domain, results, ignore_hash=False, fast=False):
    """Filter out obvious false positives.

    When *fast* is True a lightweight mode is used which **skips** the costly
    cURL/hash/content-inspection step. This is useful for quick scans where you
    only care about basic heuristics and drastically improves performance when
    working with huge wordlists or many domains.
    """

    print(f"[~] Filtering for {domain} – raw: {len(results)} (fast={fast})")
    
    # Pre-scan for catch-all pages
    if not fast and domain not in catch_all_domains:
        is_catch_all, catch_all_hash, catch_all_size = detect_catch_all_page(domain)
        catch_all_domains[domain] = (is_catch_all, catch_all_hash, catch_all_size)
        if is_catch_all:
            print(f"[!] Detected catch-all page for {domain} (size={catch_all_size})")

    # Step 1: heuristic filtering (length + pattern)
    freq = {}
    for r in results:
        freq[r["length"]] = freq.get(r["length"], 0) + 1
    
    # Find the most common length and also lengths that appear frequently
    common_len = max(freq.keys(), key=lambda k: freq[k]) if freq else None
    
    # Calculate threshold for "too common" lengths (dynamic based on results)
    total_results = len(results)
    # Adaptive threshold: 10% for small scans, 8% for medium, 6% for large scans
    if total_results < 100:
        threshold_percentage = 0.10  # 10%
    elif total_results < 500:
        threshold_percentage = 0.08  # 8%
    else:
        threshold_percentage = 0.06  # 6%
    
    common_length_threshold = max(3, int(total_results * threshold_percentage))
    
    # Find all lengths that appear too frequently
    too_common_lengths = {length: count for length, count in freq.items() 
                         if count >= common_length_threshold}

    base_kw = {"admin", "login", "dashboard", "config", "debug", "upload", "backup"}
    kw_set = base_kw | set(DOMAIN_OVERRIDES.get(domain.lower(), {}).get("keywords", []))

    stage1 = []
    # Get dynamic exclude patterns for this domain
    exclude_patterns = get_exclude_patterns(domain)
    
    for r in results:
        url, status, length = r["url"].lower(), r["status"], r["length"]

        # Check against dynamic exclude patterns
        if any(re.search(pat, url) for pat in exclude_patterns):
            log_skipped_endpoint(r["url"], reason="pattern-skip")
            continue

        # NOTE: Previously we skipped wildcard or dot-prefixed filenames because many
        # frameworks routed them to catch-all pages.  This was hiding potentially
        # interesting findings (.env, .git, etc.).  The logic is now removed so the
        # scanner keeps these paths.  If you need the old behaviour use a future CLI
        # flag to re-enable it.
        
        # Skip 403 Forbidden responses early
        if status == 403:
            log_skipped_endpoint(r["url"], reason="status-403")
            continue

        # Skip 0-byte responses (likely redirects with no body or dead endpoints)
        if length == 0:
            log_skipped_endpoint(r["url"], reason="size-0")
            continue

        kw_hit = any(k in url for k in kw_set)
        short_rd = status in (301, 302) and "." not in r["path"].split("/")[-1]

        # Enhanced filtering: check if length is too common
        length_too_common = length in too_common_lengths
        
        # Keep if: good status AND (length is not too common OR has keywords OR is short redirect)
        keep = status in (200, 301, 302) and (not length_too_common or kw_hit or short_rd)
        
        if keep:
            stage1.append(r)
        else:
            if length_too_common:
                log_skipped_endpoint(r["url"], reason="length-too-common")
            else:
                log_skipped_endpoint(r["url"], reason="length-filter")

    print(f"[~] After heuristic pass: {len(stage1)} kept / {len(results)-len(stage1)} skipped")

    # Step 2: Deep inspection (skip when fast=True)
    curl_results = {}
    if not fast:
        urls_to_check = [r["url"] for r in stage1]
        curl_results = parallel_curl_fetch(urls_to_check, max_workers=10)

    # Count hash frequencies for soft-404 detection
    hash_freq   = defaultdict(int)
    fuzzy_freq  = defaultdict(int)  # new
    if not fast:
        for url, result in curl_results.items():
            if result[1]:  # body_hash
                hash_freq[result[1]] += 1

            # Track fuzzy clusters (group by high similarity)
            fz = result[2] or ""
            if fz:
                matched_key = None
                for existing in fuzzy_freq.keys():
                    try:
                        if ssdeep.compare(fz, existing) > 90:
                            matched_key = existing
                            break
                    except Exception:
                        pass
                if matched_key:
                    fuzzy_freq[matched_key] += 1
                else:
                    fuzzy_freq[fz] = 1
    
    # If a hash appears in >30% of results, it's likely a soft-404
    soft_404_threshold = max(3, len(stage1) * 0.3)
    common_hashes  = {h for h, count in hash_freq.items()  if count >= soft_404_threshold}
    common_fuzzes = {h for h, count in fuzzy_freq.items() if count >= soft_404_threshold}
    
    clusters = defaultdict(list)
    for r in stage1:
        if fast:
            # Minimal placeholders to keep downstream code happy
            is_soft = False
            body_hash = None
            fuzzy_hash = ""
            final_status = r.get("status")
            is_downloadable = False
            download_meta = None
            vt_result = None
            tech = None
        else:
            is_soft, body_hash, fuzzy_hash, final_status, is_downloadable, download_meta, vt_result, tech = curl_results.get(r["url"], (False, None, None, None, False, None, None, None))
            
            # Mark as soft-404 if hash is too common or final status is 5xx
            if body_hash in common_hashes or fuzzy_hash in common_fuzzes or (final_status and final_status >= 500):
                is_soft = True
                
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
    seen_sha1  = set()  # fallback dedup when ssdeep unavailable/disabled
    
    # Track counts by status
    new_count = 0
    changed_count = 0
    existing_count = 0

    for key, items in clusters.items():
        probe = items[0]
        if fast:
            # Minimal placeholders to keep downstream code happy
            is_soft = False
            body_hash = None
            fuzzy_hash = ""
            final_status = probe.get("status")
            is_downloadable = False
            download_meta = None
            vt_result = None
            tech = None
        else:
            is_soft, body_hash, fuzzy_hash, final_status, is_downloadable, download_meta, vt_result, tech = curl_results.get(probe["url"], (False, None, None, None, False, None, None, None))

        if is_soft or fuzzy_hash in common_fuzzes:
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

                # Fallback duplicate check (sha1) – kicks in when fuzzy hashing is
                # unavailable (empty string) or when the ssdeep module is missing.
                body_h = itm.get("body_hash")
                if body_h and body_h in seen_sha1:
                    log_skipped_endpoint(itm["url"], reason="sha1-dupe")
                    continue
                if body_h:
                    seen_sha1.add(body_h)

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
        # Scan full large file for secrets (may be slow)
        try:
            from utils.secret_scan import scan_secrets_bytes
            th_res = scan_secrets_bytes(body_bytes)
            if th_res:
                meta["th_secrets"] = th_res
                logging.info("[secrets] TruffleHog found %d secrets", len(th_res))
        except Exception:
            pass

        meta["note"] = f"Large file – scanned entire {size//1024//1024} MB file"
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

            # 1️⃣  Simple regex-based secret detection (quick)
            found = []
            for pat in SECRET_PATTERNS:
                if pat.search(text):
                    found.append(pat.pattern)
            if found:
                meta["potential_secrets"] = list(set(found))
                logging.info("[secrets] Regex secrets hit %d patterns", len(found))

            # 2️⃣  TruffleHog scan (if available) – richer discovery
            try:
                from utils.secret_scan import scan_secrets_bytes
                th_res = scan_secrets_bytes(body_bytes)  # scan full content
                if th_res:
                    meta["th_secrets"] = th_res
                    logging.info("[secrets] TruffleHog found %d secrets", len(th_res))
            except Exception:
                pass


        except Exception:
            pass

    return meta

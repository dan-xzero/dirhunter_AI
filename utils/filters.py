# File: dirhunter_ai/utils/filters.py

import subprocess, os, hashlib, datetime, ssdeep, requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.db_handler import init_db, get_stored_hash, update_hash_record, track_finding, get_finding_status

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
    if url in curl_cache:
        return curl_cache[url]

    try:
        resp = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)

        final_status = resp.status_code
        content_type = resp.headers.get("content-type", "").lower()
        content_disposition = resp.headers.get("content-disposition", "").lower()

        # Heuristic: treat as downloadable if binary or explicit attachment
        is_downloadable = (
            ("application/" in content_type and not content_type.startswith("application/json")) or
            ("octet-stream" in content_type) or
            ("attachment" in content_disposition)
        )

        body_bytes = resp.content or b""

        try:
            body_text = body_bytes.decode("utf-8", errors="ignore").lower()
        except Exception:
            body_text = ""

        is_soft = any(p in body_text for p in SOFT_404_PHRASES)

        sha1_hash = hashlib.sha1(body_bytes).hexdigest()
        fuzzy_hash = ssdeep.hash(body_text) if body_text else ssdeep.hash("")

        curl_cache[url] = (is_soft, sha1_hash, fuzzy_hash, final_status, is_downloadable)
    except Exception:
        curl_cache[url] = (False, None, None, None, False)

    return curl_cache[url]

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
        is_soft, body_hash, fuzzy_hash, final_status, is_downloadable = curl_results.get(r["url"], (False, None, None, None, False))
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
        is_soft, _, _, _, _ = curl_results.get(probe["url"], (False, None, None, None, False))

        if is_soft:
            for itm in items:
                log_skipped_endpoint(itm["url"], reason="curl-soft404")
            print(f"[~] Cluster {key} soft-404 → {len(items)} skipped")
        else:
            for itm in items:
                # Fuzzy duplicate check
                if any(ssdeep.compare(itm["fuzzy_hash"], seen) > 90 for seen in seen_fuzzy):
                    log_skipped_endpoint(itm["url"], reason="fuzzy-dupe")
                    continue
                seen_fuzzy.append(itm["fuzzy_hash"])

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

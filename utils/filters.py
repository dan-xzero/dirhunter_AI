# File: dirhunter_ai/utils/filters.py

import subprocess, os, hashlib, datetime, ssdeep
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.db_handler import init_db, get_stored_hash, update_hash_record

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

curl_cache = {}  # url → (is_soft404, sha1_hash, fuzzy_hash)
init_db()

# ─────────── LOG HELPERS ───────────
def log_skipped_endpoint(url: str, reason: str = "unknown"):
    entry = f"[{reason}] {url}"
    with open(SKIPPED_FILE, "a") as f:
        f.write(entry + "\n")

def log_kept_endpoint(url: str):
    with open(KEPT_FILE, "a") as f:
        f.write(url + "\n")

def log_summary(domain, raw_count, after_heuristic, after_cluster):
    with open(SUMMARY_FILE, "a") as f:
        f.write(f"Domain: {domain}\n")
        f.write(f"Raw results: {raw_count}\n")
        f.write(f"After heuristic: {after_heuristic}\n")
        f.write(f"After cluster (new/changed only): {after_cluster}\n\n")

# ─────────── CURL FETCHER ───────────
def curl_fetch_hash(url):
    if url in curl_cache:
        return curl_cache[url]
    try:
        r = subprocess.run(["curl", "-L", "-s", "--max-time", "10", url],
                           capture_output=True, text=True)
        body = r.stdout.lower()
        is_soft = any(p in body for p in SOFT_404_PHRASES)
        sha1_hash = hashlib.sha1(body.encode("utf-8")).hexdigest()
        fuzzy_hash = ssdeep.hash(body)
        curl_cache[url] = (is_soft, sha1_hash, fuzzy_hash)
    except Exception:
        curl_cache[url] = (False, None, None)
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
                results[url] = (False, None, None)
    return results

# ─────────── MAIN FILTER ───────────
def filter_false_positives(domain, results, ignore_hash=False):
    print(f"[~] Filtering for {domain} – raw: {len(results)}")

    # Step 1: heuristic filtering (length + pattern)
    freq = {}
    for r in results:
        freq[r["length"]] = freq.get(r["length"], 0) + 1
    common_len = max(freq, key=freq.get) if freq else None

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
        is_soft, body_hash, fuzzy_hash = curl_results.get(r["url"], (False, None, None))
        r["body_hash"] = body_hash
        r["fuzzy_hash"] = fuzzy_hash
        clusters[(r["status"], r["length"], body_hash)].append(r)

    final = []
    seen_fuzzy = []

    for key, items in clusters.items():
        probe = items[0]
        is_soft, _, _ = curl_results.get(probe["url"], (False, None, None))

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

                # Final storage/hash comparison
                if ignore_hash:
                    final.append(itm)
                    log_kept_endpoint(itm["url"])
                else:
                    stored_hash = get_stored_hash(itm["url"])
                    if stored_hash == itm["body_hash"]:
                        log_skipped_endpoint(itm["url"], reason="hash-unchanged")
                    else:
                        final.append(itm)
                        log_kept_endpoint(itm["url"])
                        update_hash_record(itm["url"], itm["body_hash"])

    print(f"[+] Final count for {domain}: {len(final)} (new/changed, kept list in {KEPT_FILE})")
    log_summary(domain, raw_count=len(results), after_heuristic=len(stage1), after_cluster=len(final))
    return final

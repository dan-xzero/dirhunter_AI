# File: dirhunter_ai/main.py (with --screenshot-workers flag)
import os, traceback, sys
from utils.scanner import run_ffuf
from utils.filters import filter_false_positives
from utils.screenshot import take_screenshots_parallel
from utils.ai_analyzer import classify_screenshot_with_gpt
from utils.slack_alert import send_slack_alert
from utils.reporter import export_tag_based_reports
from utils.db_handler import reset_db
from config import WORDLIST, EXTENSIONS, THREADS, WEBHOOK_URL, SCREENSHOT_DIR, RAW_RESULTS_DIR

SKIPPED_FILE = "skipped_domains.txt"
IGNORE_HASH_MODE = "--ignore-hash" in sys.argv
RESET_DB_MODE = "--reset-db" in sys.argv

# Default parallel worker count
screenshot_workers = 5
for i, arg in enumerate(sys.argv):
    if arg == "--screenshot-workers" and i + 1 < len(sys.argv):
        try:
            screenshot_workers = int(sys.argv[i + 1])
        except ValueError:
            print("[!] Invalid --screenshot-workers value, using default (5)")

if RESET_DB_MODE:
    reset_db()
    sys.exit(0)

# ------------ helpers -----------------
def load_domains(file_path="domain.txt"):
    with open(file_path) as f:
        return [d.strip() for d in f if d.strip()]

def log_skipped(domain):
    if not os.path.exists(SKIPPED_FILE):
        open(SKIPPED_FILE, "w").close()
    with open(SKIPPED_FILE) as f:
        already = {d.strip() for d in f.readlines()}
    if domain not in already:
        with open(SKIPPED_FILE, "a") as f:
            f.write(domain + "\n")
        print(f"[!] Logged skipped domain → {SKIPPED_FILE}: {domain}")

def force_trailing_slash_if_needed(url, status):
    if status in (301, 302) and not url.endswith("/") and "." not in url.split("/")[-1]:
        return url + "/"
    return url

def safe_filename(path_frag):
    for ch in r"\\/:*?\"<>|":
        path_frag = path_frag.replace(ch, "_")
    return path_frag.strip("_") or "root"

# ------------ constants ---------------
HIGH_SIGNAL_TAGS = {
    "Credentials/Secrets", "Database", "Backup", "Logs/Debug",
    "Config/Environment", "Source Code", "Admin Panel", "Login Panel",
    "Payment Info", "PII/User Data", "Internal/Restricted"
}

# ------------ main workflow -----------
def process_target(domain: str):
    try:
        print(f"\n[+] Scanning: {domain}")
        os.makedirs(f"{RAW_RESULTS_DIR}/{domain}", exist_ok=True)
        os.makedirs(f"{SCREENSHOT_DIR}/{domain}", exist_ok=True)

        raw = run_ffuf(domain, WORDLIST, EXTENSIONS,
                       threads=20, rate=30, delay="0.2-1.0")

        if not raw:
            print(f"[!] No results from FFUF → skipping {domain}")
            log_skipped(domain)
            return False

        filtered = filter_false_positives(domain, raw, ignore_hash=IGNORE_HASH_MODE)
        if not filtered:
            print(f"[!] Nothing left after filtering → skipping {domain}")
            log_skipped(domain)
            return False

        screenshot_tasks = []
        for entry in filtered:
            entry["url"] = force_trailing_slash_if_needed(entry["url"], entry["status"])
            shot = os.path.join(SCREENSHOT_DIR, domain, safe_filename(entry["path"]) + ".png")
            entry["screenshot"] = shot
            screenshot_tasks.append({"url": entry["url"], "output_path": shot})

        take_screenshots_parallel(screenshot_tasks, max_workers=screenshot_workers)

        high_signal = []
        for entry in filtered:
            entry["ai_tag"] = classify_screenshot_with_gpt(entry["screenshot"]) if os.path.exists(entry["screenshot"]) else "Unknown"
            if entry["ai_tag"] in HIGH_SIGNAL_TAGS:
                high_signal.append(entry)

        print(f"[~] High-signal findings: {len(high_signal)}")

        for finding in high_signal:
            send_slack_alert(finding, WEBHOOK_URL)

        export_tag_based_reports(domain, filtered)
        print(f"[✔] Finished domain: {domain}")
        return True

    except Exception as e:
        print(f"[!] Fatal error on {domain}: {e}")
        traceback.print_exc()
        log_skipped(domain)
        return False


def main():
    for target in load_domains():
        process_target(target)

if __name__ == "__main__":
    main()

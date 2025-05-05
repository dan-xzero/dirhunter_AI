import os, sys, traceback, logging, argparse
from dotenv import load_dotenv
from utils.scanner import run_ffuf
from utils.filters import filter_false_positives
from utils.screenshot import take_screenshots_parallel
from utils.ai_analyzer import classify_screenshot_with_gpt
from utils.slack_alert import send_slack_alert
from utils.reporter import export_tag_based_reports
from utils.db_handler import reset_db
from utils.tag_validator import validate_tagged_entry
from config import EXTENSIONS, THREADS, SCREENSHOT_DIR, RAW_RESULTS_DIR

load_dotenv(override=True)
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

# ──────────── LOGGING SETUP ────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("dirhunter_ai.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ──────────── CLI ARGUMENTS ────────────
def parse_args():
    parser = argparse.ArgumentParser(description="DirHunter AI - Advanced Fuzzing Pipeline")
    parser.add_argument("--domains", type=str, help="Comma-separated domains or path to a domains file")
    parser.add_argument("--wordlist", type=str, help="Path to wordlist file")
    parser.add_argument("--ignore-hash", action="store_true", help="Ignore stored hash DB")
    parser.add_argument("--reset-db", action="store_true", help="Reset the hash database")
    parser.add_argument("--screenshot-workers", type=int, default=5, help="Number of parallel screenshot workers (default: 5)")
    return parser.parse_args()

# ──────────── HELPERS ────────────
def load_domains(file_path):
    if os.path.exists(file_path):
        with open(file_path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return []

def log_skipped(domain, skipped_file="skipped_domains.txt"):
    if not os.path.exists(skipped_file):
        open(skipped_file, "w").close()
    with open(skipped_file) as f:
        already = {d.strip() for d in f.readlines()}
    if domain not in already:
        with open(skipped_file, "a") as f:
            f.write(domain + "\n")
        logger.warning(f"Logged skipped domain → {skipped_file}: {domain}")

def force_trailing_slash_if_needed(url, status):
    if status in (301, 302) and not url.endswith("/") and "." not in url.split("/")[-1]:
        return url + "/"
    return url

def safe_filename(path_frag):
    for ch in r"\\/:*?\"<>|":
        path_frag = path_frag.replace(ch, "_")
    return path_frag.strip("_") or "root"

def process_target(domain, wordlist, ignore_hash, screenshot_workers):
    try:
        logger.info(f"Scanning: {domain} with wordlist {wordlist}")
        os.makedirs(f"{RAW_RESULTS_DIR}/{domain}", exist_ok=True)
        os.makedirs(f"{SCREENSHOT_DIR}/{domain}", exist_ok=True)

        raw = run_ffuf(domain, wordlist, EXTENSIONS, threads=THREADS, rate=30, delay="0.2-1.0")
        if not raw:
            logger.warning(f"No results from FFUF → skipping {domain}")
            log_skipped(domain)
            return False

        filtered = filter_false_positives(domain, raw, ignore_hash=ignore_hash)
        if not filtered:
            logger.warning(f"Nothing left after filtering → skipping {domain}")
            log_skipped(domain)
            return False

        screenshot_tasks = []
        for entry in filtered:
            entry["url"] = force_trailing_slash_if_needed(entry["url"], entry["status"])
            shot_path = os.path.join(SCREENSHOT_DIR, domain, safe_filename(entry["path"]) + ".png")
            entry["screenshot"] = shot_path
            screenshot_tasks.append({"url": entry["url"], "output_path": shot_path})

        take_screenshots_parallel(screenshot_tasks, max_workers=screenshot_workers)

        for entry in filtered:
            if os.path.exists(entry["screenshot"]):
                entry["ai_tag"] = classify_screenshot_with_gpt(entry["screenshot"])
            else:
                entry["ai_tag"] = "Unknown"

            if not validate_tagged_entry(entry):
                entry["ai_tag"] = "Other"

        export_tag_based_reports(domain, filtered)

        if WEBHOOK_URL and WEBHOOK_URL.lower() != "none":
            send_slack_alert(domain, filtered, WEBHOOK_URL)
        else:
            logger.warning("WEBHOOK_URL not set. Skipping Slack alert.")

        logger.info(f"Finished domain: {domain}")
        return True

    except Exception as e:
        logger.error(f"Fatal error on {domain}: {e}")
        traceback.print_exc()
        log_skipped(domain)
        return False

# ──────────── MAIN ENTRY ────────────
def main():
    args = parse_args()

    if args.reset_db:
        reset_db()
        logger.info("Hash database reset.")
        sys.exit(0)

    # Load from CLI if given
    if args.domains:
        if os.path.isfile(args.domains):
            domains = load_domains(args.domains)
        else:
            domains = [d.strip() for d in args.domains.split(",") if d.strip()]
        if not args.wordlist:
            logger.error("When using --domains, you must also provide --wordlist.")
            sys.exit(1)
        wordlist = args.wordlist
        for domain in domains:
            process_target(domain, wordlist=wordlist, ignore_hash=args.ignore_hash, screenshot_workers=args.screenshot_workers)
    else:
        # Default prod/nonprod mode
        prod_domains = load_domains("domains/prod_domains.txt")
        nonprod_domains = load_domains("domains/nonprod_domains.txt")

        for domain in prod_domains:
            process_target(domain, wordlist="wordlists/wordlist_prod.txt", ignore_hash=args.ignore_hash, screenshot_workers=args.screenshot_workers)

        for domain in nonprod_domains:
            process_target(domain, wordlist="wordlists/wordlist_nonprod.txt", ignore_hash=args.ignore_hash, screenshot_workers=args.screenshot_workers)

if __name__ == "__main__":
    main()

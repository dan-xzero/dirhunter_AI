import os, sys, traceback, logging, argparse
from dotenv import load_dotenv
from utils.scanner import run_ffuf, retry_rate_limited_paths
from utils.filters import filter_false_positives
from utils.screenshot import take_screenshots_parallel
from utils.ai_analyzer import classify_screenshot_with_gpt, batch_classify_screenshots
from utils.slack_alert import send_consolidated_slack_alert, send_rate_limit_alert, send_critical_alert
from utils.reporter import export_tag_based_reports, create_dashboard
from utils.db_handler import reset_db, init_db, batch_track_findings
from utils.tag_validator import validate_tagged_entry
from utils.performance import PerformanceTracker
from config import EXTENSIONS, THREADS, SCREENSHOT_DIR, RAW_RESULTS_DIR
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import multiprocessing
import queue
import threading
import time
from datetime import datetime

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

# ──────────── PERFORMANCE CONFIG ────────────
MAX_PARALLEL_DOMAINS = 10  # Process up to 10 domains concurrently
BATCH_SIZE = 20  # Batch size for AI classification
DB_WRITE_QUEUE_SIZE = 100  # Batch database writes
CRITICAL_PRIORITY_THRESHOLD = 9  # Send immediate alerts for priority >= 9

# ──────────── CLI ARGUMENTS ────────────
def parse_args():
    parser = argparse.ArgumentParser(description="DirHunter AI - Advanced Fuzzing Pipeline (Optimized)")
    parser.add_argument("--domains", type=str, help="Comma-separated domains or path to a domains file")
    parser.add_argument("--wordlist", type=str, help="Path to wordlist file")
    parser.add_argument("--ignore-hash", action="store_true", help="Show all findings including existing ones")
    parser.add_argument("--reset-db", action="store_true", help="Reset the hash database")
    parser.add_argument("--screenshot-workers", type=int, default=5, help="Number of parallel screenshot workers (default: 5)")
    parser.add_argument("--retry-rate-limits", action="store_true", help="Retry previously rate-limited paths")
    parser.add_argument("--parallel-domains", type=int, default=5, help="Number of domains to scan in parallel (default: 5)")
    parser.add_argument("--no-critical-alerts", action="store_true", help="Disable real-time critical alerts")
    parser.add_argument("--performance-report", action="store_true", help="Generate performance metrics report")
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

# ──────────── CRITICAL ALERT HANDLER ────────────
def check_and_send_critical_alerts(domain, findings, no_critical_alerts=False):
    """Check for critical findings and send immediate alerts"""
    if no_critical_alerts or not WEBHOOK_URL:
        return
    
    critical_findings = []
    from utils.ai_analyzer import get_category_priority
    for finding in findings:
        if finding is None:
            continue
        priority = get_category_priority(finding.get('ai_tag', 'Other'))
        if priority >= CRITICAL_PRIORITY_THRESHOLD:
            critical_findings.append(finding)
    
    if critical_findings:
        logger.info(f"Found {len(critical_findings)} critical findings for {domain}")
        send_critical_alert(domain, critical_findings, WEBHOOK_URL)

# ──────────── OPTIMIZED DOMAIN PROCESSOR ────────────
def process_domain_optimized(domain, wordlist, ignore_hash, screenshot_workers, no_critical_alerts=False):
    """Optimized domain processing"""
    start_time = time.time()
    perf_metrics = {}
    
    try:
        logger.info(f"[Process {os.getpid()}] Scanning: {domain}")
        os.makedirs(f"{RAW_RESULTS_DIR}/{domain}", exist_ok=True)
        os.makedirs(f"{SCREENSHOT_DIR}/{domain}", exist_ok=True)

        # Track performance
        scan_start = time.time()
        
        # Run FFUF with optimized settings
        raw, rate_limited = run_ffuf(domain, wordlist, EXTENSIONS, threads=THREADS, rate=30, delay="0.2-1.0")
        
        scan_duration = time.time() - scan_start
        perf_metrics['scan_time'] = scan_duration
        
        if rate_limited:
            logger.warning(f"Found {len(rate_limited)} rate-limited paths for {domain}")
            perf_metrics['rate_limits'] = len(rate_limited)
        
        if not raw:
            logger.warning(f"No results from FFUF → skipping {domain}")
            log_skipped(domain)
            return None, perf_metrics

        # Filter with performance tracking
        filter_start = time.time()
        filtered = filter_false_positives(domain, raw, ignore_hash=ignore_hash)
        filter_duration = time.time() - filter_start
        perf_metrics['filter_time'] = filter_duration
        
        if not filtered:
            logger.warning(f"Nothing left after filtering → skipping {domain}")
            log_skipped(domain)
            return None, perf_metrics

        # Prepare screenshot tasks – skip direct downloads
        screenshot_tasks = []
        for entry in filtered:
            entry["url"] = force_trailing_slash_if_needed(entry["url"], entry["status"])

            # Direct download? – no screenshot / classification necessary
            if entry.get("downloadable"):
                entry["screenshot"] = ""
                # Tag already set in filter stage but double-check
                entry.setdefault("ai_tag", "Downloadable File")
                continue

            shot_path = os.path.join(SCREENSHOT_DIR, domain, safe_filename(entry["path"]) + ".png")
            entry["screenshot"] = shot_path
            screenshot_tasks.append({
                "url": entry["url"],
                "output_path": shot_path,
                "screenshot_path": shot_path
            })

        # Take screenshots in parallel
        screenshot_start = time.time()
        take_screenshots_parallel(screenshot_tasks, max_workers=screenshot_workers)
        screenshot_duration = time.time() - screenshot_start
        perf_metrics['screenshot_time'] = screenshot_duration

        # Batch classify screenshots
        classification_start = time.time()
        classification_tasks = []
        for entry in filtered:
            if entry.get("screenshot") and os.path.exists(entry["screenshot"]):
                text_path = entry["screenshot"].rsplit('.',1)[0] + '.txt'
                page_text = ''
                if os.path.exists(text_path):
                    try:
                        with open(text_path, 'r', encoding='utf-8') as tp:
                            page_text = tp.read()
                    except Exception:
                        pass
                classification_tasks.append({
                    "screenshot_path": entry["screenshot"],
                    "url": entry["url"],
                    "page_text": page_text
                })
        
        if classification_tasks:
            classifications = batch_classify_screenshots(classification_tasks, max_workers=3)
            for entry in filtered:
                if entry["screenshot"] in classifications:
                    entry["ai_tag"] = classifications[entry["screenshot"]]
                else:
                    entry["ai_tag"] = "Unknown"
        else:
            for entry in filtered:
                entry["ai_tag"] = "Unknown"
        
        classification_duration = time.time() - classification_start
        perf_metrics['classification_time'] = classification_duration

        # Validate tags
        for entry in filtered:
            if entry is None:
                continue
            if not validate_tagged_entry(entry):
                entry["ai_tag"] = "Other"

        # Check for critical findings and send immediate alerts
        check_and_send_critical_alerts(domain, filtered, no_critical_alerts)

        # Export reports
        export_tag_based_reports(domain, filtered)

        # Record total time
        total_duration = time.time() - start_time
        perf_metrics['total_time'] = total_duration
        perf_metrics['findings_count'] = len(filtered)
        
        logger.info(f"Finished domain: {domain} in {total_duration:.2f}s")
        return filtered, perf_metrics

    except Exception as e:
        logger.error(f"Fatal error on {domain}: {e}")
        traceback.print_exc()
        log_skipped(domain)
        perf_metrics['error'] = str(e)
        return None, perf_metrics

# ──────────── PARALLEL DOMAIN PROCESSOR ────────────
def process_domains_parallel(domains_with_wordlists, args):
    """Process multiple domains in parallel"""
    all_results = {}
    perf_data = {}
    
    # Use ProcessPoolExecutor for true parallelism
    max_workers = min(args.parallel_domains, MAX_PARALLEL_DOMAINS, len(domains_with_wordlists))
    
    logger.info(f"Starting parallel processing with {max_workers} workers for {len(domains_with_wordlists)} domains")
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Submit all domain processing tasks
        future_to_domain = {}
        for domain, wordlist in domains_with_wordlists:
            future = executor.submit(
                process_domain_optimized,
                domain, 
                wordlist,
                args.ignore_hash,
                args.screenshot_workers,
                args.no_critical_alerts
            )
            future_to_domain[future] = domain
        
        # Collect results as they complete
        completed = 0
        total = len(domains_with_wordlists)
        
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            completed += 1
            
            try:
                results, perf_metrics = future.result()
                if results:
                    all_results[domain] = results
                perf_data[domain] = perf_metrics
                logger.info(f"Progress: {completed}/{total} domains completed")
            except Exception as e:
                logger.error(f"Domain {domain} failed: {e}")
                traceback.print_exc()
    
    return all_results, perf_data

# ──────────── BATCH DATABASE WRITER ────────────
class BatchDatabaseWriter:
    """Handles batch database writes for better performance"""
    def __init__(self, batch_size=DB_WRITE_QUEUE_SIZE):
        self.batch_size = batch_size
        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        self.writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self.writer_thread.start()
    
    def _writer_loop(self):
        """Background thread that writes to database in batches"""
        batch = []
        while not self.stop_event.is_set():
            try:
                # Get items from queue with timeout
                item = self.queue.get(timeout=1)
                batch.append(item)
                
                # Write batch if it's full
                if len(batch) >= self.batch_size:
                    batch_track_findings(batch)
                    batch = []
            except queue.Empty:
                # Write remaining items if any
                if batch:
                    batch_track_findings(batch)
                    batch = []
    
    def add_finding(self, finding_data):
        """Add a finding to the write queue"""
        self.queue.put(finding_data)
    
    def flush(self):
        """Flush all pending writes"""
        self.stop_event.set()
        self.writer_thread.join()

# ──────────── MAIN ENTRY ────────────
def main():
    # Cleanup old results before starting new scan
    try:
        from utils.cleanup import cleanup_old_runs
        cleanup_old_runs()
    except Exception as e:
        logger.warning(f"Cleanup failed: {e}")

    args = parse_args()
    
    # Initialize database
    init_db()

    if args.reset_db:
        reset_db()
        logger.info("Hash database reset.")
        sys.exit(0)

    # Initialize batch database writer
    db_writer = BatchDatabaseWriter()

    # Collect domains and wordlists
    domains_with_wordlists = []
    
    if args.domains:
        if os.path.isfile(args.domains):
            domains = load_domains(args.domains)
        else:
            domains = [d.strip() for d in args.domains.split(",") if d.strip()]
        
        if not args.wordlist:
            logger.error("When using --domains, you must also provide --wordlist.")
            sys.exit(1)
        
        wordlist = args.wordlist
        domains_with_wordlists = [(domain, wordlist) for domain in domains]
    else:
        # Default prod/nonprod mode
        prod_domains = load_domains("domains/prod_domains.txt")
        nonprod_domains = load_domains("domains/nonprod_domains.txt")
        
        for domain in prod_domains:
            domains_with_wordlists.append((domain, "wordlists/wordlist_prod.txt"))
        
        for domain in nonprod_domains:
            domains_with_wordlists.append((domain, "wordlists/wordlist_nonprod.txt"))

    # Process domains in parallel
    start_time = time.time()
    all_results, perf_data = process_domains_parallel(domains_with_wordlists, args)
    
    # Flush database writes
    db_writer.flush()
    
    # Retry rate-limited paths if requested
    if args.retry_rate_limits:
        logger.info("Retrying rate-limited paths...")
        # TODO: Implement parallel retry logic
    
    # Create dashboard if we have results
    if all_results:
        dashboard_path = create_dashboard(all_results)
        logger.info(f"Dashboard created: {dashboard_path}")
        
        # Update run history stats for timeline
        try:
            total_new = sum(sum(1 for f in fs if f.get('finding_status') == 'new') for fs in all_results.values())
            total_changed = sum(sum(1 for f in fs if f.get('finding_status') == 'changed') for fs in all_results.values())
            from utils.run_history import record_run
            record_run(total_domains=len(all_results), new_findings=total_new, changed_findings=total_changed)
        except Exception as e:
            logger.warning(f"Run history update failed: {e}")

        # Send daily digest (non-critical findings)
        if WEBHOOK_URL and WEBHOOK_URL.lower() != "none":
            # Filter out critical findings that were already sent
            non_critical_results = {}
            for domain, findings in all_results.items():
                non_critical = []
                for finding in findings:
                    from utils.ai_analyzer import get_category_priority
                    priority = get_category_priority(finding.get('ai_tag', 'Other'))
                    if priority < CRITICAL_PRIORITY_THRESHOLD:
                        non_critical.append(finding)
                if non_critical:
                    non_critical_results[domain] = non_critical
            
            if non_critical_results:
                send_consolidated_slack_alert(non_critical_results, WEBHOOK_URL)
        else:
            logger.warning("WEBHOOK_URL not set. Skipping Slack alert.")
    else:
        logger.warning("No results found across all domains.")

    # Generate performance report
    if args.performance_report:
        total_time = time.time() - start_time
        perf_tracker = PerformanceTracker()
        
        # Populate performance tracker with collected data
        for domain, metrics in perf_data.items():
            if 'scan_time' in metrics:
                perf_tracker.record_scan_time(domain, metrics['scan_time'])
            if 'filter_time' in metrics:
                perf_tracker.record_filter_time(domain, metrics['filter_time'])
            if 'screenshot_time' in metrics:
                perf_tracker.record_screenshot_time(domain, metrics['screenshot_time'])
            if 'classification_time' in metrics:
                perf_tracker.record_classification_time(domain, metrics['classification_time'])
            if 'total_time' in metrics:
                perf_tracker.record_total_time(domain, metrics['total_time'])
            if 'findings_count' in metrics:
                perf_tracker.record_findings(domain, metrics['findings_count'])
            if 'rate_limits' in metrics:
                perf_tracker.record_rate_limits(domain, metrics['rate_limits'])
            if 'error' in metrics:
                perf_tracker.record_error(domain, metrics['error'])
        
        perf_report = perf_tracker.generate_report(total_time)
        logger.info("\n" + perf_report)
        
        # Save performance report
        with open(f"performance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "w") as f:
            f.write(perf_report)

    logger.info(f"All scans completed in {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    # Set multiprocessing start method
    multiprocessing.set_start_method('spawn', force=True)
    main() 
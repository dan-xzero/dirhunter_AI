import os, sys, traceback, logging, argparse

# Suppress MallocStackLogging warnings on macOS
os.environ['MallocStackLogging'] = '0'

from dotenv import load_dotenv
from utils.scanner import run_ffuf, retry_rate_limited_paths
from utils.filters import filter_false_positives
from utils.screenshot import take_screenshots_parallel, filter_screenshot_tasks, prioritize_screenshot_tasks, initialize_screenshot_system
from utils.ai_analyzer import classify_screenshot_with_gpt, batch_classify_screenshots
from utils.slack_alert import send_consolidated_slack_alert, send_rate_limit_alert, send_critical_alert, send_simple_slack_message
from utils.reporter import export_tag_based_reports, create_dashboard
from utils.enhanced_reporter import create_enhanced_dashboard
from utils.enhanced_slack import send_enhanced_slack_alert
from utils.db_handler import reset_db, init_db, batch_track_findings
from utils.tag_validator import validate_tagged_entry
from utils.performance import PerformanceTracker
from utils.dns_check import pre_scan_dns_check
from config import EXTENSIONS, THREADS, SCREENSHOT_DIR, RAW_RESULTS_DIR
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import multiprocessing
import queue
import threading
import time
import socket
from datetime import datetime

# Import resource manager if available
try:
    from utils.resource_manager import resource_manager
except ImportError:
    resource_manager = None

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
    parser.add_argument("--screenshot-workers", type=int, default=3, help="Number of parallel screenshot workers (default: 3)")
    parser.add_argument("--retry-rate-limits", action="store_true", help="Retry previously rate-limited paths")
    parser.add_argument("--parallel-domains", type=int, default=3, help="Number of domains to scan in parallel (default: 3)")
    parser.add_argument("--no-critical-alerts", action="store_true", help="Disable real-time critical alerts")
    parser.add_argument("--performance-report", action="store_true", help="Generate performance metrics report")
    parser.add_argument("--fast-filter", action="store_true", help="Skip deep curl/hash checks to speed up filtering")
    parser.add_argument("--lightweight-screenshots", action="store_true", help="[DISABLED] Always using full browser screenshots as requested")
    parser.add_argument("--optimize-resources", action="store_true", help="Enable resource optimization (default: enabled)")
    parser.add_argument("--disable-resource-optimization", action="store_true", help="Disable resource optimization")
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
        tag = finding.get('ai_tag', 'Unknown')
        priority = get_category_priority(tag)
        if priority >= CRITICAL_PRIORITY_THRESHOLD:
            critical_findings.append(finding)
    
    if critical_findings:
        logger.info(f"Found {len(critical_findings)} critical findings for {domain}")
        send_critical_alert(domain, critical_findings)

# ──────────── OPTIMIZED DOMAIN PROCESSOR ────────────
def process_domain_optimized(domain, wordlist, ignore_hash, screenshot_workers, no_critical_alerts=False, fast_filter=False, lightweight_screenshots=False):
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
        filtered = filter_false_positives(domain, raw, ignore_hash=ignore_hash, fast=fast_filter)
        filter_duration = time.time() - filter_start
        perf_metrics['filter_time'] = filter_duration
        
        if not filtered:
            logger.warning(f"Nothing left after filtering → skipping {domain}")
            log_skipped(domain)
            return None, perf_metrics

        # Pre-filter to reduce screenshot workload
        unique_findings = filter_screenshot_tasks(filtered)
        
        # Prepare screenshot tasks – skip direct downloads
        screenshot_tasks = []
        screenshot_map = {}  # url -> screenshot path for duplicates
        
        for entry in filtered:
            entry["url"] = force_trailing_slash_if_needed(entry["url"], entry["status"])

            # Direct download? – no screenshot / classification necessary
            if entry.get("downloadable"):
                entry["screenshot"] = ""
                # Tag already set in filter stage but double-check
                entry.setdefault("ai_tag", "Downloadable File")
                continue

            # Check if this is a duplicate
            if entry.get('screenshot_duplicate_of'):
                # Will use the screenshot from the representative
                continue
                
            # Only create screenshot task if this is a unique finding
            if entry in unique_findings:
                shot_path = os.path.join(SCREENSHOT_DIR, domain, safe_filename(entry["path"]) + ".png")
                entry["screenshot"] = shot_path
                screenshot_map[entry["url"]] = shot_path
                
                # Determine priority for this screenshot
                # Priority only affects order, not screenshot method
                priority = "normal"
                path_lower = entry["path"].lower()
                
                # Higher priority for sensitive paths (processed first)
                sensitive_terms = ['login', 'admin', 'dashboard', 'config', 'setup', 
                                 'install', 'phpinfo', 'backup', '.git', '.env']
                if any(term in path_lower for term in sensitive_terms):
                    priority = "high"
                
                # Lower priority for static files (processed last)
                if any(ext in path_lower for ext in ['.css', '.js', '.png', '.jpg', '.gif']):
                    priority = "low"
                
                # Don't use lightweight mode - user wants full screenshots for all paths
                # Even with --lightweight-screenshots option set
                
                screenshot_tasks.append({
                    "url": entry["url"],
                    "output_path": shot_path,
                    "screenshot_path": shot_path,
                    "priority": priority
                })

        # Initialize screenshot system before starting
        initialize_screenshot_system(max_workers=screenshot_workers)
        
        # Take screenshots in parallel with priority ordering
        screenshot_start = time.time()
        take_screenshots_parallel(screenshot_tasks, max_workers=screenshot_workers)
        
        # Assign screenshots to duplicates
        for entry in filtered:
            if entry.get('screenshot_duplicate_of') and entry['screenshot_duplicate_of'] in screenshot_map:
                entry["screenshot"] = screenshot_map[entry['screenshot_duplicate_of']]
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
                if entry.get("screenshot") in classifications:
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

# ──────────── SHARED RESULTS DICTIONARY ────────────
class SharedResults:
    """Thread-safe shared results container for updating the dashboard"""
    def __init__(self):
        self.lock = threading.RLock()
        self.results = {}
    
    def update(self, domain, findings):
        with self.lock:
            self.results[domain] = findings
    
    def get_all(self):
        with self.lock:
            return self.results.copy()

# ──────────── PARALLEL DOMAIN PROCESSOR ────────────
def process_domains_parallel(domains_with_wordlists, args, shared_results):
    """Process multiple domains in parallel with process pool"""
    results = {}
    perf_data = {}
    total = len(domains_with_wordlists)
    completed = 0
    
    # Throttle based on resources
    if resource_manager:
        recommended_domains, recommended_shots = resource_manager.get_recommended_concurrency()
        
        # Update args if auto-scaling is enabled
        if not args.disable_resource_optimization:
            if args.parallel_domains > recommended_domains:
                logger.warning(f"Reducing parallel domains from {args.parallel_domains} to {recommended_domains} based on system resources")
                args.parallel_domains = recommended_domains
                
            if args.screenshot_workers > recommended_shots:
                logger.warning(f"Reducing screenshot workers from {args.screenshot_workers} to {recommended_shots} based on system resources")
                args.screenshot_workers = recommended_shots
    
    # Clean up browser environment before starting
    try:
        from utils.screenshot import clean_browser_environment
        clean_browser_environment()
    except Exception as e:
        logger.warning(f"Browser environment cleanup failed: {e}")
    
    max_workers = min(args.parallel_domains, len(domains_with_wordlists))
    logger.info(f"Starting parallel processing with {max_workers} workers for {len(domains_with_wordlists)} domains")
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_domain = {}
        for domain, wordlist in domains_with_wordlists:
            future = executor.submit(
                process_domain_optimized,
                domain,
                wordlist,
                args.ignore_hash,
                args.screenshot_workers,
                args.no_critical_alerts,
                args.fast_filter,
                args.lightweight_screenshots
            )
            future_to_domain[future] = domain
        
        # Process as they complete
        try:
            # Create initial dashboard early
            dashboard_path = f"{RAW_RESULTS_DIR}/dashboard.html"
            create_dashboard(shared_results.get_all(), dashboard_path)
            
            # Process completed domains
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    findings, metrics = future.result()
                    
                    # Store results
                    if findings:
                        results[domain] = findings
                        shared_results.update(domain, findings)
                        perf_data[domain] = metrics
                    
                    # Update dashboard periodically
                    completed += 1
                    if completed % 3 == 0 or completed == total:
                        try:
                            # Update main dashboard
                            create_dashboard(shared_results.get_all(), dashboard_path)
                            
                            # Try to update enhanced dashboard
                            try:
                                enhanced_dashboard_path = f"{RAW_RESULTS_DIR}/enhanced_dashboard.html"
                                create_enhanced_dashboard(shared_results.get_all(), enhanced_dashboard_path)
                            except Exception as e:
                                logger.warning(f"Enhanced dashboard update failed: {e}")
                        except Exception as e:
                            pass
                            
                    logger.info(f"Progress: {completed}/{total} domains completed")
                except Exception as e:
                    logger.error(f"Domain {domain} failed: {e}")
                    traceback.print_exc()
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user. Saving partial results...")
            # Handle graceful shutdown
        
        # Kill any remaining browser processes
        if resource_manager:
            resource_manager.kill_browser_processes()
    
    return results, perf_data

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

    # Start resource monitoring if available
    if resource_manager and not args.disable_resource_optimization:
        resource_manager.start_monitoring()
        
        # Get recommended concurrency
        recommended_domains, recommended_shots = resource_manager.get_recommended_concurrency()
        
        # Auto-adjust concurrency settings
        if args.parallel_domains > recommended_domains:
            logger.warning(f"Reducing --parallel-domains from {args.parallel_domains} to {recommended_domains} based on system resources")
            args.parallel_domains = recommended_domains
            
        if args.screenshot_workers > recommended_shots:
            logger.warning(f"Reducing --screenshot-workers from {args.screenshot_workers} to {recommended_shots} based on system resources")
            args.screenshot_workers = recommended_shots
    
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
        # Production vs Non-Production
        from domains.prod_domains import PROD_DOMAINS
        from domains.nonprod_domains import NONPROD_DOMAINS
        
        # Skip DNS check for --retry-rate-limits
        if args.retry_rate_limits:
            # For retries, use the list of domains with previous rate limits
            from utils.rate_control import load_rate_limited_domains
            domains = load_rate_limited_domains()
            domains_with_wordlists = [(domain, "wordlists/wordlist_prod.txt") for domain in domains]
        else:
            # Default: scan prod domains with prod wordlist, nonprod with nonprod wordlist
            domains_with_wordlists = [
                (domain, "wordlists/wordlist_prod.txt") for domain in PROD_DOMAINS
            ] + [
                (domain, "wordlists/wordlist_nonprod.txt") for domain in NONPROD_DOMAINS
            ]
    
    # Validate domains with DNS lookup (skip for retry mode)
    if not args.retry_rate_limits:
        all_domains = [domain for domain, _ in domains_with_wordlists]
        valid_domains = pre_scan_dns_check(all_domains)
        if not valid_domains:
            logger.error("No valid domains to scan after DNS validation.")
            sys.exit(1)
        
        # Filter out invalid domains
        domains_with_wordlists = [(domain, wordlist) 
                                 for domain, wordlist in domains_with_wordlists 
                                 if domain in valid_domains]
    
    # Create shared results container
    shared_results = SharedResults()
    
    try:
        # Create initial dashboard
        logger.info("Creating initial dashboard...")
        dashboard_path = f"{RAW_RESULTS_DIR}/dashboard.html"
        create_dashboard({}, dashboard_path)
        
        # Try to create enhanced dashboard
        try:
            enhanced_dashboard_path = f"{RAW_RESULTS_DIR}/enhanced_dashboard.html"
            logger.info("Creating initial enhanced dashboard...")
            create_enhanced_dashboard({}, enhanced_dashboard_path)
        except Exception as e:
            logger.warning(f"Initial enhanced dashboard creation failed: {e}")
    except Exception:
        pass
    
    # Start performance tracking
    perf = PerformanceTracker()
    start_time = time.time()
    
    # Process domains
    if args.retry_rate_limits:
        # Retry mode: only retry previously rate-limited paths
        logger.info("Retrying rate-limited paths...")
        results = retry_rate_limited_paths()
    else:
        # Normal scan mode: process all domains with concurrency
        results, perf_data = process_domains_parallel(domains_with_wordlists, args, shared_results)
        perf.add_metrics(perf_data)
    
    # Create final dashboard
    try:
        dashboard_path = f"{RAW_RESULTS_DIR}/dashboard.html"
        create_dashboard(results, dashboard_path)
        logger.info(f"Final dashboard created: {dashboard_path}")
        
        # Create enhanced dashboard
        try:
            enhanced_dashboard_path = f"{RAW_RESULTS_DIR}/enhanced_dashboard.html"
            create_enhanced_dashboard(results, enhanced_dashboard_path)
            logger.info(f"Enhanced dashboard created: {enhanced_dashboard_path}")
        except Exception as e:
            logger.warning(f"Enhanced dashboard creation failed: {e}")
            
        # Add to run history
        try:
            from utils.run_history import update_run_history
            update_run_history(results, domains_with_wordlists)
        except Exception as e:
            logger.warning(f"Run history update failed: {e}")
    except Exception:
        pass
    
    # Flush database writer
    db_writer.flush()
    
    # Send Slack summary (if webhook is set)
    if WEBHOOK_URL and results:
        try:
            send_consolidated_slack_alert(results)
            
            # Enhanced Slack report - removed as requested
        except Exception:
            pass
    elif not WEBHOOK_URL:
        logger.warning("WEBHOOK_URL not set. Skipping Slack alert.")
    elif not results:
        logger.warning("No results found across all domains.")
    
    # Show performance report if requested
    if args.performance_report:
        perf_report = perf.generate_report()
        print("\n" + "="*80)
        print("PERFORMANCE REPORT")
        print("="*80)
        print(perf_report)
    
    # Stop resource monitoring if it was started
    if resource_manager:
        resource_manager.stop_monitoring()
    
    logger.info(f"All scans completed in {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        sys.exit(0) 
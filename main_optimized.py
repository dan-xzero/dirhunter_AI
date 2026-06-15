import os, sys, traceback, logging, argparse
import requests

# Suppress MallocStackLogging warnings on macOS
os.environ['MallocStackLogging'] = '0'

from dotenv import load_dotenv
from utils.scanner import run_ffuf, retry_rate_limited_paths
from utils.filters import filter_false_positives
from utils.screenshot import take_screenshots_parallel, filter_screenshot_tasks, initialize_screenshot_system
from utils.false_positive_filter import apply_false_positive_filter
from utils.smart_filter import SmartFilter
from utils.ai_analyzer import classify_screenshot_with_gpt, batch_classify_screenshots
from utils.slack_alert import send_consolidated_slack_alert, send_rate_limit_alert, send_critical_alert, send_simple_slack_message
from utils.reporter import export_tag_based_reports, create_dashboard

from utils.enhanced_slack import send_enhanced_slack_alert
from utils.db_handler import reset_db, init_db, batch_track_findings
from utils.tag_validator import validate_tagged_entry
from utils.performance import PerformanceTracker
from utils.dns_check import pre_scan_dns_check
from utils.findings_enricher import enrich_findings
from config import (
    EXTENSIONS,
    KILL_BROWSER_SESSIONS,
    RAW_RESULTS_DIR,
    SCREENSHOT_DIR,
    THREADS,
    USE_LEGACY_HTML,
    USE_LLM_VALIDATOR,
    USE_NEW_SLACK,
    USE_PG,
)
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
import multiprocessing
import queue
import threading
import time
import socket
from datetime import datetime
import subprocess

# Import resource manager if available
try:
    from utils.resource_manager import resource_manager
except ImportError:
    resource_manager = None

from utils.fingerprint_manager import detect_technologies_for_url

def send_chunked_slack_message(webhook_url, title, message, link=None, link_text=None):
    """
    Send a Slack message with automatic chunking for large messages
    
    Parameters:
    - webhook_url: The Slack webhook URL
    - title: The message title
    - message: The message body (will be chunked if too large)
    - link: Optional URL to include
    - link_text: Text for the link button
    """
    if not webhook_url or webhook_url.lower() == "none":
        return False
    
    # Split message into chunks if it's too long
    max_chunk_size = 2000  # Leave buffer for Slack limits
    
    if len(message) <= max_chunk_size:
        # Message is small enough, send as single message
        from utils.slack_alert import send_simple_slack_message
        return send_simple_slack_message(webhook_url, title, message, link, link_text)
    
    # Message is too large, split into chunks
    print(f"[!] Message is large ({len(message)} chars), splitting into chunks...")
    
    # Split by double newlines to preserve formatting
    message_parts = message.split("\n\n")
    chunks = []
    current_chunk = ""
    
    for part in message_parts:
        # If adding this part would exceed chunk size, start a new chunk
        if len(current_chunk) + len(part) + 2 > max_chunk_size:
            if current_chunk:
                chunks.append(current_chunk.strip())
            current_chunk = part
        else:
            if current_chunk:
                current_chunk += "\n\n" + part
            else:
                current_chunk = part
    
    # Add the last chunk if it has content
    if current_chunk.strip():
        chunks.append(current_chunk.strip())
    
    # Send each chunk as a separate message
    success = True
    for i, chunk in enumerate(chunks):
        chunk_title = f"{title} (Part {i+1}/{len(chunks)})" if len(chunks) > 1 else title
        
        # Only add link to the last chunk
        chunk_link = link if i == len(chunks) - 1 else None
        chunk_link_text = link_text if i == len(chunks) - 1 else None
        
        from utils.slack_alert import send_simple_slack_message
        chunk_success = send_simple_slack_message(
            webhook_url, 
            chunk_title, 
            chunk, 
            chunk_link, 
            chunk_link_text
        )
        
        if not chunk_success:
            success = False
            print(f"[!] Failed to send chunk {i+1}/{len(chunks)}")
        
        # Small delay between chunks to avoid rate limiting
        if i < len(chunks) - 1:
            time.sleep(1)
    
    return success

def capture_headers(url, timeout=10):
    """
    Capture response headers for a given URL
    
    Args:
        url: URL to capture headers from
        timeout: Request timeout in seconds
        
    Returns:
        dict: Headers dictionary or empty dict if failed
    """
    try:
        from utils.user_agent_manager import get_realistic_headers
        headers = get_realistic_headers(include_scanner_header=True)
        
        response = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True)
        
        # Convert headers to a more readable format
        captured_headers = {}
        for header_name, header_value in response.headers.items():
            # Skip some headers that are not security-relevant
            if header_name.lower() not in ['server', 'date', 'connection', 'transfer-encoding']:
                captured_headers[header_name] = header_value
        
        return captured_headers
        
    except Exception as e:
        logger.debug(f"Failed to capture headers for {url}: {e}")
        return {}


def finding_path_priority(entry):
    """Prefer human-reviewable paths when duplicate app shells collapse to one finding."""
    path = (entry.get("path") or "").strip("/").lower()
    priority_terms = [
        ("login", 0),
        ("signin", 0),
        ("auth", 0),
        ("admin", 1),
        ("dashboard", 1),
        ("manage", 1),
        ("api/docs", 2),
        ("swagger", 2),
        ("robots.txt", 8),
        ("sitemap.xml", 8),
    ]
    for term, priority in priority_terms:
        if term in path:
            return (priority, len(path), path)
    return (5, len(path), path)


def count_wordlist_urls(wordlist):
    """Count URL candidates ffuf will attempt for a single domain."""
    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def nonprod_only_enabled():
    return os.getenv("DIRHUNTER_NONPROD_ONLY", "1").lower() in {"1", "true", "yes", "on"}


def looks_prod_like(domain):
    value = (domain or "").strip().lower()
    host = value.split("/", 1)[0]
    path = value[len(host):]
    prod_host_terms = ("api-prod", ".prod.", "-prod.", ".prod-", "-prod-", "production")
    if host == "prod" or host.startswith("prod.") or host.endswith(".prod"):
        return True
    if any(term in host for term in prod_host_terms):
        return True
    return any(segment == "prod" or segment.startswith("prod-") for segment in path.split("/") if segment)


def enforce_nonprod_only(domains_with_wordlists):
    if not nonprod_only_enabled():
        return
    blocked = [
        domain
        for domain, wordlist in domains_with_wordlists
        if "wordlist_prod" in (wordlist or "").lower() or looks_prod_like(domain)
    ]
    if blocked:
        sample = ", ".join(blocked[:5])
        logger.error(f"Blocked prod-like scan target(s) while DIRHUNTER_NONPROD_ONLY is enabled: {sample}")
        sys.exit(2)


def summarize_scan_metrics(perf_data, domains_with_wordlists):
    domain_urls_scanned = {}
    for domain, wordlist in domains_with_wordlists:
        metrics = (perf_data or {}).get(domain) or {}
        domain_urls_scanned[domain] = int(metrics.get("urls_scanned") or count_wordlist_urls(wordlist))

    return {
        "urls_scanned": sum(domain_urls_scanned.values()),
        "domain_urls_scanned": domain_urls_scanned,
    }


load_dotenv(override=True)
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

# Add the aggressive_browser_cleanup function near the top after imports
def aggressive_browser_cleanup():
    """Aggressively clean up all browser processes"""
    if not KILL_BROWSER_SESSIONS:
        logger.info("Skipping aggressive browser cleanup because DIRHUNTER_KILL_BROWSER_SESSIONS is disabled")
        return

    try:
        logger.info("Performing aggressive browser cleanup...")
        
        # Force kill ALL Firefox and Chrome processes
        subprocess.run(
            "pkill -9 -f 'firefox|firefox-bin|chrome|chromium'", 
            shell=True, stderr=subprocess.DEVNULL
        )
        
        # Force kill ALL driver processes
        subprocess.run(
            "pkill -9 -f 'geckodriver|chromedriver'", 
            shell=True, stderr=subprocess.DEVNULL
        )
        
        # Force kill ALL Xvfb processes
        subprocess.run(
            "pkill -9 -f 'Xvfb'", 
            shell=True, stderr=subprocess.DEVNULL
        )
        
        # Kill any puppeteer processes that might be started by Wappalyzer
        subprocess.run(
            "pkill -9 -f 'puppeteer|node.*wappalyzer'", 
            shell=True, stderr=subprocess.DEVNULL
        )
        
        # Kill any remaining zombie processes
        subprocess.run(
            "pkill -9 -f 'zombie'", 
            shell=True, stderr=subprocess.DEVNULL
        )
        
        # Verify we got them all
        count_cmd = "ps aux | grep -E 'firefox|chrome|chromium|gecko|selenium|xvfb|puppeteer' | grep -v grep | wc -l"
        result = subprocess.run(count_cmd, shell=True, text=True, capture_output=True)
        try:
            remaining = int(result.stdout.strip())
            if remaining > 0:
                logger.warning(f"Browser cleanup detected {remaining} remaining processes")
                
                # Try again with more aggressive approach (lower priority processes)
                subprocess.run("pkill -9 -f 'browser|webkit|electron'", shell=True, stderr=subprocess.DEVNULL)
            else:
                logger.info("All browser processes successfully terminated")
        except Exception:
            pass
    except Exception as e:
        logger.error(f"Error during aggressive browser cleanup: {e}")

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
    parser.add_argument("--lightweight-screenshots", action="store_true", help="[DEPRECATED] Option no longer used, full screenshots are always generated")
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
def process_domain_optimized(domain, wordlist, ignore_hash, screenshot_workers, no_critical_alerts=False, fast_filter=False):
    """
    Process a single domain with optimized workflow
    
    Args:
        domain: Domain to scan
        wordlist: Path to wordlist file
        ignore_hash: Whether to ignore previous scan hash
        screenshot_workers: Max parallel screenshot workers
        no_critical_alerts: Disable critical alerts
        fast_filter: Use fast filtering
    """
    start_time = time.time()
    perf_metrics = {"urls_scanned": count_wordlist_urls(wordlist)}
    
    # Clean up any browser processes at the start of each domain
    aggressive_browser_cleanup()
    
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
        raw = sorted(raw, key=finding_path_priority)
        filtered = filter_false_positives(domain, raw, ignore_hash=ignore_hash, fast=fast_filter)
        filter_duration = time.time() - filter_start
        perf_metrics['filter_time'] = filter_duration
        
        if not filtered:
            logger.warning(f"Nothing left after filtering → skipping {domain}")
            log_skipped(domain)
            return None, perf_metrics

        # Enhanced filtering with additional modules
        enhanced_filter_start = time.time()
        
        # Initialize smart filter
        smart_filter = SmartFilter()
        
        # Adapt smart filter to domain characteristics
        smart_filter.adapt_to_domain(domain, filtered)
        
        # Apply additional false positive filtering
        logger.info(f"Applying enhanced false positive filtering to {len(filtered)} results...")
        enhanced_filtered = []
        filtered = sorted(filtered, key=finding_path_priority)
        
        for entry in filtered:
            # Skip if already marked as downloadable
            if entry.get("downloadable"):
                enhanced_filtered.append(entry)
                continue
                
            # Apply smart filtering
            is_fp, reason = smart_filter.is_likely_false_positive(
                entry["url"], 
                entry.get("content", ""), 
                domain
            )
            
            if is_fp:
                logger.debug(f"Smart filter rejected {entry['url']}: {reason}")
                continue
                
            # Apply false positive filter
            if not apply_false_positive_filter(entry, enhanced_filtered):
                logger.debug(f"False positive filter rejected {entry['url']}")
                continue
                
            enhanced_filtered.append(entry)
        
        # Update filtered results
        filtered = enhanced_filtered
        enhanced_filter_duration = time.time() - enhanced_filter_start
        perf_metrics['enhanced_filter_time'] = enhanced_filter_duration
        
        logger.info(f"Enhanced filtering: {len(filtered)} results kept from {len(raw)} raw results")
        
        if not filtered:
            logger.warning(f"Nothing left after enhanced filtering → skipping {domain}")
            log_skipped(domain)
            return None, perf_metrics

        # Pre-filter to reduce screenshot workload
        unique_findings = filter_screenshot_tasks(filtered)
        
        # Prepare screenshot tasks
        screenshot_tasks = []
        screenshot_map = {}  # url -> screenshot path for duplicates
        
        # Capture headers for all findings
        logger.info(f"Capturing headers for {len(filtered)} findings...")
        for entry in filtered:
            entry["url"] = force_trailing_slash_if_needed(entry["url"], entry["status"])

            # Capture headers for each finding
            headers = capture_headers(entry["url"])
            if headers:
                entry["headers"] = headers
                logger.info(f"Captured {len(headers)} headers for {entry['url']}")
            else:
                logger.info(f"No headers captured for {entry['url']}")

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
                
                # Add task as tuple for new format (url, path, priority)
                screenshot_tasks.append((entry["url"], shot_path, priority))
                
        # Initialize screenshot system before starting
        initialize_screenshot_system(max_workers=screenshot_workers)
        
        # Take screenshots in parallel with the optimized method
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

        # Process headers for JSON serialization
        for entry in filtered:
            if 'headers' in entry:
                # Ensure headers is a dict for proper JSON serialization
                if not isinstance(entry['headers'], dict):
                    entry['headers'] = dict(entry['headers'])
                logger.info(f"Processed headers for {entry['url']}: {list(entry['headers'].keys())}")

        # Enrich findings with additional data (including headers)
        try:
            enrich_findings(domain, filtered)
            logger.info(f"Enriched {len(filtered)} findings for {domain}")
        except Exception as e:
            logger.error(f"Failed to enrich findings for {domain}: {e}")

        if USE_LLM_VALIDATOR and filtered:
            try:
                from utils.llm_validator import validate_batch

                filtered = validate_batch(filtered)
                logger.info(f"Validated {len(filtered)} findings with LLM for {domain}")
            except Exception as e:
                logger.error(f"LLM finding validation failed for {domain}: {e}")

        # Check for critical findings and send immediate alerts
        check_and_send_critical_alerts(domain, filtered, no_critical_alerts)

        # Export legacy HTML reports while the portal migration is in dual-write mode.
        if USE_LEGACY_HTML:
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
        recommended_domains = resource_manager.get_recommended_concurrency()
        
        # Update args if auto-scaling is enabled
        if not args.disable_resource_optimization:
            if args.parallel_domains > recommended_domains:
                logger.warning(f"Reducing parallel domains from {args.parallel_domains} to {recommended_domains} based on system resources")
                args.parallel_domains = recommended_domains
            
            # No need to adjust screenshot workers as we're now using sequential processing
    
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
                args.fast_filter
            )
            future_to_domain[future] = domain
        
        # Process as they complete
        try:
            # Create initial dashboard early
            dashboard_path = os.path.join("results", "html", "dashboard.html")
            if USE_LEGACY_HTML:
                create_dashboard(shared_results.get_all(), dashboard_path)
            
            # Process completed domains
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    findings, metrics = future.result()
                    
                    # Store results and metrics even when no findings survive filtering.
                    perf_data[domain] = metrics or {}
                    if findings:
                        results[domain] = findings
                        shared_results.update(domain, findings)
                    
                    # Update dashboard periodically
                    completed += 1
                    if completed % 3 == 0 or completed == total:
                        try:
                            # Update main dashboard in HTML_REPORT_DIR
                            dashboard_path = os.path.join("results", "html", "dashboard.html")
                            if USE_LEGACY_HTML:
                                create_dashboard(shared_results.get_all(), dashboard_path)
                            
                        except Exception as e:
                            logger.warning(f"Dashboard update failed: {e}")
                            
                    logger.info(f"Progress: {completed}/{total} domains completed")
                except Exception as e:
                    logger.error(f"Domain {domain} failed: {e}")
                    traceback.print_exc()
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user. Saving partial results...")
            # Handle graceful shutdown
        
        # Kill any remaining browser processes
        if resource_manager and KILL_BROWSER_SESSIONS:
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
    """Main entry point for DirHunter AI"""
    # Aggressive cleanup at program start
    aggressive_browser_cleanup()
    
    # Cleanup old results before starting new scan
    try:
        from utils.cleanup import cleanup_old_runs
        cleanup_old_runs()
    except Exception as e:
        logger.warning(f"Cleanup failed: {e}")
    
    # Set environment variables to prevent browser usage in any Node.js/Puppeteer processes
    os.environ["PUPPETEER_SKIP_CHROMIUM_DOWNLOAD"] = "true"
    os.environ["WAPPALYZER_BROWSER"] = "false"
    os.environ["NODE_OPTIONS"] = "--max-old-space-size=256"
    
    # Parse arguments
    args = parse_args()
    
    # Start resource monitoring if available
    if resource_manager and not args.disable_resource_optimization:
        resource_manager.start_monitoring()
        
        # Get recommended concurrency
        recommended_domains = resource_manager.get_recommended_concurrency()
        
        # Auto-adjust concurrency settings
        if args.parallel_domains > recommended_domains:
            logger.warning(f"Reducing --parallel-domains from {args.parallel_domains} to {recommended_domains} based on system resources")
            args.parallel_domains = recommended_domains
        
        # No need to adjust screenshot workers as we're using sequential processing
    
    # Initialize database
    init_db()

    if args.reset_db:
        reset_db()
        logger.info("Hash database reset.")
        sys.exit(0)

    pg_scan_id = None
    partial_pg_scan = os.getenv("DIRHUNTER_PARTIAL_SCAN", "0").lower() in {"1", "true", "yes", "on"}

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
        # Load domains from text files
        prod_domains = load_domains("domains/prod_domains.txt")
        nonprod_domains = load_domains("domains/nonprod_domains.txt")
        
        # Skip DNS check for --retry-rate-limits
        if args.retry_rate_limits:
            # For retries, use the list of domains with previous rate limits
            from utils.rate_control import load_rate_limited_domains
            domains = load_rate_limited_domains()
            retry_wordlist = "wordlists/wordlist_nonprod.txt" if nonprod_only_enabled() else "wordlists/wordlist_prod.txt"
            domains_with_wordlists = [(domain, retry_wordlist) for domain in domains]
        else:
            # Default: scan prod domains with prod wordlist, nonprod with nonprod wordlist
            domains_with_wordlists = [(domain, "wordlists/wordlist_nonprod.txt") for domain in nonprod_domains]
            if not nonprod_only_enabled():
                domains_with_wordlists = [
                    (domain, "wordlists/wordlist_prod.txt") for domain in prod_domains
                ] + domains_with_wordlists

    enforce_nonprod_only(domains_with_wordlists)
    
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
    if USE_PG:
        try:
            from app.services.findings import create_scan_sync

            if os.getenv("SCAN_ID"):
                pg_scan_id = int(os.getenv("SCAN_ID"))
            else:
                pg_scan_id = create_scan_sync(
                    trigger="cron" if not args.domains else "manual",
                    wordlist=args.wordlist,
                    args=vars(args),
                )
            logger.info(f"Created Postgres scan record: {pg_scan_id}")
        except Exception as e:
            logger.error(f"Postgres scan creation failed; continuing with legacy storage: {e}")
            pg_scan_id = None
    
    try:
        # Create initial dashboard
        if USE_LEGACY_HTML:
            logger.info("Creating initial dashboard...")
            dashboard_path = os.path.join("results", "html", "dashboard.html")
            create_dashboard({}, dashboard_path)
        

            
        # Get server hostname for dashboard URL
        # Use REPORT_BASE_URL for dashboard URL
        REPORT_BASE_URL = os.getenv("REPORT_BASE_URL")
        if USE_PG and os.getenv("PORTAL_BASE_URL"):
            dashboard_url = f"{os.getenv('PORTAL_BASE_URL').rstrip('/')}/scans/{pg_scan_id or ''}"
        elif REPORT_BASE_URL:
            dashboard_url = f"{REPORT_BASE_URL}/reports/dashboard.html"
        else:
            # Fallback to local IP if REPORT_BASE_URL not set
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            dashboard_url = f"http://{ip_address}/results/html/dashboard.html"
        
        # New Slack mode sends the structured completion digest only; avoid legacy-format start messages.
        if WEBHOOK_URL and WEBHOOK_URL.lower() != "none" and not USE_NEW_SLACK and not partial_pg_scan:
            total_domains = len(domains_with_wordlists)
            start_message = (
                f":mag: *DirHunter AI Scan Started*\n"
                f"• Domains to scan: {total_domains}\n"
                f"• Parallel domains: {args.parallel_domains}\n"
                f"• Screenshot workers: {args.screenshot_workers}\n"
            )
            
            send_chunked_slack_message(
                WEBHOOK_URL,
                "DirHunter AI Scan Started",
                start_message,
                dashboard_url,
                "View Live Dashboard"
            )
    except Exception as e:
        logger.warning(f"Initial setup error: {e}")
    
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
        dashboard_path = os.path.join("results", "html", "dashboard.html")
        if USE_LEGACY_HTML:
            create_dashboard(results, dashboard_path)
            logger.info(f"Final dashboard created: {dashboard_path}")
        
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

    if USE_PG and pg_scan_id:
        try:
            from app.services.findings import persist_batch_sync, persist_and_complete_scan_sync, update_scan_state_sync

            scan_metric_stats = summarize_scan_metrics(perf_data, domains_with_wordlists)
            if scan_metric_stats:
                update_scan_state_sync(pg_scan_id, stats=scan_metric_stats)

            if partial_pg_scan:
                pg_stats = persist_batch_sync(pg_scan_id, results or {})
            else:
                pg_stats = persist_and_complete_scan_sync(pg_scan_id, results or {}, status="completed")
            logger.info(f"Postgres dual-write complete for scan {pg_scan_id}: {pg_stats}")
        except Exception as e:
            logger.error(f"Postgres dual-write failed for scan {pg_scan_id}: {e}")
            try:
                from app.services.findings import complete_scan_sync

                if not partial_pg_scan:
                    complete_scan_sync(pg_scan_id, status="failed", stats={"error": str(e)})
            except Exception:
                pass
    
    # Send Slack summary (if webhook is set)
    if WEBHOOK_URL and USE_NEW_SLACK and pg_scan_id and not partial_pg_scan:
        try:
            from app.services.slack import send_digest_sync

            if send_digest_sync(pg_scan_id, WEBHOOK_URL):
                logger.info("Slack digest sent successfully")
            else:
                logger.error("Slack digest failed")
        except Exception as e:
            logger.error(f"Slack digest failed with exception: {e}")
    elif WEBHOOK_URL and not partial_pg_scan:
        try:
            # Calculate key statistics
            total_domains = len(results) if results else 0
            total_findings = sum(len(findings) for findings in results.values()) if results else 0
            new_findings = sum(sum(1 for f in fs if f.get('finding_status') == 'new') for fs in results.values()) if results else 0
            changed_findings = sum(sum(1 for f in fs if f.get('finding_status') == 'changed') for fs in results.values()) if results else 0
            existing_findings = sum(sum(1 for f in fs if f.get('finding_status') == 'existing') for fs in results.values()) if results else 0
            scan_duration = time.time() - start_time

            # Get new findings only
            new_findings_list = []
            if results:
                for domain, findings_list in results.items():
                    for finding in findings_list:
                        if finding.get('finding_status') == 'new':
                            finding_entry = {
                                'domain': domain,
                                'url': finding.get('url', ''),
                                'path': finding.get('path', ''),
                                'tag': finding.get('ai_tag', 'Unknown')
                            }
                            new_findings_list.append(finding_entry)

            # Sort by domain
            new_findings_list.sort(key=lambda x: (x['domain'], x['tag'], x['url']))

            # Generate domain stats
            domain_stats = []
            if results:
                for domain, findings in results.items():
                    domain_new = sum(1 for f in findings if f.get('finding_status') == 'new')
                    domain_changed = sum(1 for f in findings if f.get('finding_status') == 'changed')
                    domain_existing = sum(1 for f in findings if f.get('finding_status') == 'existing')
                    domain_stats.append({
                        'domain': domain, 
                        'new': domain_new, 
                        'changed': domain_changed,
                        'existing': domain_existing,
                        'total': len(findings)
                    })

            # Count findings by category
            categories = defaultdict(int)
            if results:
                for domain, findings_list in results.items():
                    for finding in findings_list:
                        tag = finding.get('ai_tag', 'Other')
                        categories[tag] += 1

            # Sort categories by count
            sorted_categories = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]

            # Build concise Slack message focused on new findings
            scan_timestamp = datetime.now().strftime("%b %d, %Y at %H:%M")
            completion_message = (
                f":white_check_mark: *DirHunter AI Scan Completed*\n"
                f"Scan completed for {total_domains} domain{'s' if total_domains > 1 else ''}\n"
                f"• New findings: {new_findings}\n"
                f"• Total findings: {total_findings}\n"
                f"• Scan duration: {scan_duration:.2f} seconds\n"
                f"• Completed: {scan_timestamp}\n\n"
            )
            
            # Add new findings section grouped by domain (this will be chunked if too large)
            if new_findings_list:
                completion_message += f":new: *New Findings Detected*\n\n"
                
                # Group findings by domain
                domain_findings = {}
                for finding in new_findings_list:
                    domain = finding['domain']
                    if domain not in domain_findings:
                        domain_findings[domain] = []
                    domain_findings[domain].append(finding)
                
                # Show findings grouped by domain
                for domain, findings in domain_findings.items():
                    completion_message += f"*Domain: {domain}*\n"
                    for finding in findings:
                        # Show the complete URL without AI labels
                        url = finding['url']
                        completion_message += f"• {url}\n"
                    completion_message += "\n"  # Add spacing between domains
            
            # Add dashboard link
            completion_message += (
                f"\n:dart: *View Complete Security Dashboard*\n"
                f"Access detailed reports, screenshots, and analysis:\n"
                f":robot_face: Powered by DirHunter AI"
            )
            
            # Get dashboard URL
            REPORT_BASE_URL = os.getenv("REPORT_BASE_URL")
            if USE_PG and os.getenv("PORTAL_BASE_URL"):
                dashboard_url = f"{os.getenv('PORTAL_BASE_URL').rstrip('/')}/scans/{pg_scan_id or ''}"
            elif REPORT_BASE_URL:
                dashboard_url = f"{REPORT_BASE_URL}/reports/dashboard.html"
            else:
                # Fallback to local IP
                hostname = socket.gethostname()
                ip_address = socket.gethostbyname(hostname)
                dashboard_url = f"http://{ip_address}/results/html/dashboard.html"
            
            # Send the message with chunking support for large messages
            from utils.slack_alert import send_simple_slack_message
            success = send_chunked_slack_message(
                WEBHOOK_URL,
                "DirHunter AI Scan Completed",
                completion_message,
                dashboard_url,
                "View Dashboard"
            )
            
            if success:
                logger.info("✅ Slack completion message sent successfully")
            else:
                logger.error("❌ Failed to send Slack completion message")
            
        except Exception as e:
            logger.error(f"❌ Slack alert failed with exception: {e}")
            import traceback
            logger.error(f"❌ Exception details: {traceback.format_exc()}")
    elif not WEBHOOK_URL:
        logger.warning("WEBHOOK_URL not set. Skipping Slack alert.")
    elif not results and not partial_pg_scan:
        logger.info("No results found across all domains. Sending completion notification anyway.")
        # Send a simple completion message even when no results
        try:
            completion_message = (
                f":white_check_mark: *DirHunter AI Scan Completed*\n"
                f"Scan completed but no findings were detected.\n"
                f"• Scan duration: {time.time() - start_time:.2f} seconds\n"
                f"• Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
                f"• :robot_face: Powered by DirHunter AI"
            )
            
            success = send_chunked_slack_message(
                WEBHOOK_URL,
                "DirHunter AI Scan Completed",
                completion_message
            )
            
            if success:
                logger.info("✅ Slack completion message sent successfully (no results)")
            else:
                logger.error("❌ Failed to send Slack completion message (no results)")
                
        except Exception as e:
            logger.error(f"❌ Slack alert failed for no-results case: {e}")
    
    # Show performance report if requested
    if args.performance_report:
        try:
            perf_report = perf.generate_report(time.time() - start_time)
            print("\n" + "="*80)
            print("PERFORMANCE REPORT")
            print("="*80)
            print(perf_report)
        except Exception as e:
            logger.warning(f"Performance report generation failed: {e}")
    
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
#!/usr/bin/env python3
"""
Modified version of main_optimized.py that doesn't rely on the screenshot module
"""

import os
import sys
import logging
import time
from datetime import datetime
import socket
from collections import defaultdict
import requests

# Suppress MallocStackLogging warnings on macOS
os.environ['MallocStackLogging'] = '0'

from dotenv import load_dotenv
from utils.scanner import run_ffuf, retry_rate_limited_paths
from utils.filters import filter_false_positives
from utils.reporter import create_dashboard, export_tag_based_reports
from utils.enhanced_reporter import create_enhanced_dashboard
from utils.db_handler import reset_db, init_db, batch_track_findings
from utils.performance import PerformanceTracker
from utils.dns_check import pre_scan_dns_check
from config import EXTENSIONS, THREADS, SCREENSHOT_DIR, RAW_RESULTS_DIR
from collections import Counter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("dirhunter_ai.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Constants
HTML_REPORT_DIR = "results/html"

def safe_filename(path_frag):
    """Convert a path fragment to a safe filename"""
    for ch in r"\\/:*?\"<>|":
        path_frag = path_frag.replace(ch, "_")
    return path_frag.strip("_") or "root"

def force_trailing_slash_if_needed(url, status):
    """Add trailing slash if needed for redirects"""
    if status in (301, 302) and not url.endswith("/") and "." not in url.split("/")[-1]:
        return url + "/"
    return url

def log_skipped(domain, skipped_file="skipped_domains.txt"):
    """Log skipped domain to file"""
    if not os.path.exists(skipped_file):
        open(skipped_file, "w").close()
    with open(skipped_file) as f:
        already = {d.strip() for d in f.readlines()}
    if domain not in already:
        with open(skipped_file, "a") as f:
            f.write(domain + "\n")
        logger.warning(f"Logged skipped domain → {skipped_file}: {domain}")

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
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'
        }
        
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

def process_domain_without_screenshots(domain, wordlist, ignore_hash=False, fast_filter=False):
    """
    Process a single domain without taking screenshots
    
    Args:
        domain: Domain to scan
        wordlist: Path to wordlist file
        ignore_hash: Whether to ignore previous scan hash
        fast_filter: Use fast filtering
    """
    start_time = time.time()
    perf_metrics = {}
    
    try:
        logger.info(f"Scanning: {domain}")
        os.makedirs(f"{RAW_RESULTS_DIR}/{domain}", exist_ok=True)
        os.makedirs(f"{HTML_REPORT_DIR}/{domain}", exist_ok=True)

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

        # Process findings without screenshots and capture headers
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

            # Create placeholder paths for screenshots without actually taking them
            if not entry.get("screenshot_duplicate_of") and not entry.get("downloadable"):
                shot_path = os.path.join(HTML_REPORT_DIR, domain, safe_filename(entry["path"]) + ".png")
                entry["screenshot"] = shot_path
            
            # Assign simple tags based on path
            path_lower = entry["path"].lower()
            
            if "admin" in path_lower or "dashboard" in path_lower or "panel" in path_lower:
                entry["ai_tag"] = "Admin Panel"
            elif "login" in path_lower or "auth" in path_lower or "signin" in path_lower:
                entry["ai_tag"] = "Authentication"
            elif "api" in path_lower:
                entry["ai_tag"] = "API Endpoint"
            elif "config" in path_lower or "settings" in path_lower:
                entry["ai_tag"] = "Configuration Files"
            elif any(ext in path_lower for ext in [".js", ".css", ".html"]):
                entry["ai_tag"] = "Static Assets"
            elif "backup" in path_lower or "bak" in path_lower:
                entry["ai_tag"] = "Backup Files"
            elif "env" in path_lower or ".env" in path_lower:
                entry["ai_tag"] = "Environment Files"
            elif "git" in path_lower:
                entry["ai_tag"] = "Source Code"
            elif entry.get("downloadable"):
                entry["ai_tag"] = "Downloadable File"
            else:
                entry["ai_tag"] = "Other"

        # Record total time
        total_duration = time.time() - start_time
        perf_metrics['total_time'] = total_duration
        perf_metrics['findings_count'] = len(filtered)
        
        logger.info(f"Finished domain: {domain} in {total_duration:.2f}s")
        return filtered, perf_metrics

    except Exception as e:
        logger.error(f"Fatal error on {domain}: {e}")
        import traceback
        traceback.print_exc()
        log_skipped(domain)
        perf_metrics['error'] = str(e)
        return None, perf_metrics

def main():
    """Main entry point"""
    # Initialize performance tracker
    perf = PerformanceTracker()
    start_time = time.time()
    
    # Initialize database
    init_db()
    
    # Set up domain and wordlist
    domain = "qa.onequince.com"
    wordlist = "wordlists/wordlist_prod.txt.noslash"
    
    # Validate domain with DNS lookup
    valid_domains = pre_scan_dns_check([domain])
    if not valid_domains:
        logger.error("Domain not valid after DNS validation.")
        sys.exit(1)
    
    # Process domain
    results = {}
    logger.info(f"Starting scan for {domain}...")
    findings, perf_data = process_domain_without_screenshots(domain, wordlist, ignore_hash=False, fast_filter=False)
    
    if findings:
        results[domain] = findings
        perf.add_metrics({domain: perf_data})
        
        # Create reports
        try:
            # Export tag-based reports
            export_tag_based_reports(domain, findings, HTML_REPORT_DIR)
            
            # Create dashboard
            dashboard_path = os.path.join(HTML_REPORT_DIR, "dashboard.html")
            create_dashboard(results, dashboard_path)
            logger.info(f"Dashboard created: {dashboard_path}")
            
            # Create enhanced dashboard
            try:
                enhanced_dashboard_path = os.path.join(HTML_REPORT_DIR, "enhanced_dashboard.html")
                create_enhanced_dashboard(results, HTML_REPORT_DIR)
                logger.info(f"Enhanced dashboard created: {enhanced_dashboard_path}")
            except Exception as e:
                logger.error(f"Failed to create enhanced dashboard: {e}")
        except Exception as e:
            logger.error(f"Error creating reports: {e}")
    else:
        logger.warning(f"No findings for {domain}")
    
    # Show performance summary
    logger.info(f"Scan completed in {time.time() - start_time:.2f} seconds")
    logger.info(f"HTML reports generated in {HTML_REPORT_DIR}/")

if __name__ == "__main__":
    main() 
#!/usr/bin/env python3
"""
Screenshot Utility - Optimized implementation with progressive resource usage
"""

import os
import sys
import logging
import threading
import time
import tempfile
import uuid
import shutil
import random
from typing import Dict, List, Any, Optional, Tuple
import urllib3

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logger = logging.getLogger(__name__)

# Import resource manager
try:
    from utils.resource_manager import resource_manager
except ImportError:
    resource_manager = None
    logger.warning("Resource manager not available - using default settings")

# Check for selenium availability
_SELENIUM_AVAILABLE = False
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.firefox.service import Service as FirefoxService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    _SELENIUM_AVAILABLE = True
except ImportError:
    logger.warning("Selenium not installed - will use fallback screenshot methods")

# Detect whether pure_screenshot is available
_PURE_SCREENSHOT_AVAILABLE = False
try:
    from utils.pure_screenshot import take_screenshot as pure_take_screenshot
    _PURE_SCREENSHOT_AVAILABLE = True
except ImportError:
    _PURE_SCREENSHOT_AVAILABLE = False

# Default concurrency - will be updated by initialize_screenshot_system
_MAX_WORKERS = 1
_browser_semaphore = threading.Semaphore(1)

# Browser process timeout
_BROWSER_PROCESS_TIMEOUT = 30  # seconds

# Clean up any leftover browser processes at module import time
if resource_manager:
    try:
        resource_manager.kill_browser_processes()
        resource_manager.clean_temporary_dirs()
    except Exception:
        pass

def initialize_screenshot_system(max_workers=1):
    """Initialize the screenshot system with sequential processing
    
    Args:
        max_workers: Number of browser instances (should be 1 for sequential processing)
    """
    global _MAX_WORKERS, _browser_semaphore
    
    # Always use 1 worker for sequential processing
    _MAX_WORKERS = 1
    
    # Create new semaphore that allows only one browser at a time
    _browser_semaphore = threading.Semaphore(1)
    
    # Start resource monitoring if available
    if resource_manager:
        resource_manager.start_monitoring()
        
    logger.info("Screenshot system initialized for sequential processing")
    
    # Clean up any leftover browser processes or temp files
    clean_browser_environment()
    
def clean_browser_environment():
    """Clean up browser environment before starting"""
    # Kill stuck browser processes
    if resource_manager:
        try:
            killed = resource_manager.kill_browser_processes()
            if killed > 0:
                logger.info(f"Cleaned up {killed} browser processes")
            
            # Clean temporary directories
            cleaned = resource_manager.clean_temporary_dirs()
            if cleaned > 0:
                logger.info(f"Cleaned up {cleaned} temporary directories")
        except Exception as e:
            logger.error(f"Error during browser environment cleanup: {e}")
    
    # Always clean temp dirs by pattern
    try:
        temp_dir = tempfile.gettempdir()
        browser_patterns = ['chrome_', 'firefox_', 'gecko_', 'tmp_']
        for item in os.listdir(temp_dir):
            if any(item.startswith(pattern) for pattern in browser_patterns) and os.path.isdir(os.path.join(temp_dir, item)):
                try:
                    shutil.rmtree(os.path.join(temp_dir, item), ignore_errors=True)
                except Exception as e:
                    logger.error(f"Failed to remove temp dir {os.path.join(temp_dir, item)}: {e}")
    except Exception as e:
        logger.error(f"Error cleaning temporary directories: {e}")

def create_fallback_screenshot(url, output_path):
    """Create a fallback screenshot when Selenium fails"""
    try:
        # Try using requests to get page content
        import os
        import requests
        from PIL import Image, ImageDraw
        
        logger.info(f"Creating fallback screenshot for {url}")
        
        # Try to fetch page content
        try:
            response = requests.get(url, timeout=15, verify=False, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36'
            })
            content = response.text
            status = response.status_code
            
            # Try to extract title
            title = None
            if "<title>" in content and "</title>" in content:
                title_start = content.find("<title>") + 7
                title_end = content.find("</title>", title_start)
                title = content[title_start:title_end].strip()
        except Exception as e:
            content = None
            status = "Error"
            title = None
            logger.warning(f"Failed to fetch content from {url}: {e}")
        
        # Create a simple image with the URL and status
        width, height = 1280, 800
        img = Image.new('RGB', (width, height), color=(240, 240, 240))
        draw = ImageDraw.Draw(img)
        
        # Draw header bar
        draw.rectangle([(0, 0), (width, 60)], fill=(70, 130, 180))
        draw.text((20, 20), f"URL: {url}", fill=(255, 255, 255))
        
        # Add content info
        y_pos = 80
        draw.text((20, y_pos), f"Status: {status}", fill=(0, 0, 0))
        y_pos += 30
        
        if title:
            draw.text((20, y_pos), f"Title: {title}", fill=(0, 0, 0))
            y_pos += 30
            
        draw.text((20, y_pos), "Screenshot created with fallback method", fill=(100, 100, 100))
        y_pos += 30
        
        # Add content preview if available
        if content:
            content_preview = content[:1000].replace('\n', ' ')
            y_pos += 20
            draw.text((20, y_pos), "Content Preview:", fill=(0, 0, 0))
            y_pos += 20
            
            # Add content lines
            for i in range(0, min(800, len(content_preview)), 80):
                line = content_preview[i:i+80]
                draw.text((20, y_pos), line, fill=(60, 60, 60))
                y_pos += 20
                if y_pos > height - 20:
                    break
        
        # Ensure output directory exists
        dir_path = os.path.dirname(output_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
        
        # Save image and text
        img.save(output_path)
        logger.info(f"Fallback image saved to {output_path}")
        
        # Save text content if available
        try:
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write(content if content else f"Failed to retrieve content for {url}")
        except Exception as e:
            logger.warning(f"Failed to save text content: {e}")
        
        return True
    except Exception as e:
        logger.error(f"Fallback screenshot failed: {e}")
        
        # Last resort: create empty files
        try:
            import os
            dir_path = os.path.dirname(output_path)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
                
            with open(output_path, 'wb') as f:
                f.write(b'')
                
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write(f"Screenshot unavailable for {url}")
                
            logger.info(f"Created empty placeholder files for {url}")
        except Exception as inner_e:
            logger.error(f"Failed to create empty files: {inner_e}")
        
        # Return False but don't raise an exception
        return False

def take_screenshot(url, output_path, priority="normal"):
    """Take a screenshot of a URL with smart strategy selection
    
    Args:
        url: The URL to capture
        output_path: Where to save the screenshot
        priority: Priority level ('high', 'normal', 'low')
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Always attempt browser-based screenshots first for all priorities
        # Only use fallback if browser approach fails
        success = take_browser_screenshot(url, output_path)
        
        # If browser screenshot fails, try the fallback method
        if not success:
            logger.info(f"Browser screenshot failed, using fallback for {url}")
            return create_fallback_screenshot(url, output_path)
            
        return success
    except Exception as e:
        logger.error(f"Screenshot error for {url}: {e}")
        try:
            return create_fallback_screenshot(url, output_path)
        except Exception as e2:
            logger.error(f"Fallback also failed: {e2}")
            return False

def take_browser_screenshot(url, output_path):
    """Take a screenshot using a browser (Selenium) with minimal resource usage"""
    if not _SELENIUM_AVAILABLE:
        logger.info(f"Selenium not available - using fallback for {url}")
        return create_fallback_screenshot(url, output_path)
    
    # Wait for resource manager if needed
    if resource_manager and resource_manager.should_pause():
        logger.info(f"Waiting for resources before taking screenshot of {url}")
        resource_manager.wait_if_needed(timeout=60)  # Wait up to a minute
    
    # Acquire semaphore to limit concurrent browser instances
    if not _browser_semaphore.acquire(timeout=60):
        logger.warning(f"Semaphore timeout - using fallback for {url}")
        return create_fallback_screenshot(url, output_path)
    
    driver = None
    temp_dir = None
    success = False
    process_pid = None
    browser_type = None
    
    try:
        # Create a unique temporary directory for browser user data
        temp_dir = os.path.join(tempfile.gettempdir(), f"browser_{uuid.uuid4().hex}")
        os.makedirs(temp_dir, exist_ok=True)
        
        # Try multiple browser configurations until one succeeds
        for browser_config in get_browser_configs(temp_dir):
            try:
                # Get browser type and options
                browser_type = browser_config.get('type', 'chrome')
                options = browser_config.get('options')
                binary = browser_config.get('binary')
                
                # Setup driver with timeout
                logger.info(f"Initializing {browser_type} for {url} with config: {browser_config.get('name')}")
                
                if browser_type == 'chrome':
                    # Try to find chromedriver
                    driver_path = find_chrome_binary('chromedriver')
                    if driver_path:
                        service = ChromeService(executable_path=driver_path)
                        driver = webdriver.Chrome(service=service, options=options)
                    else:
                        # Let Selenium try to find the driver
                        driver = webdriver.Chrome(options=options)
                else:  # Firefox
                    # Try to find geckodriver
                    driver_path = find_firefox_binary('geckodriver')
                    if driver_path:
                        service = FirefoxService(executable_path=driver_path)
                        driver = webdriver.Firefox(service=service, options=options)
                    else:
                        # Let Selenium try to find the driver
                        driver = webdriver.Firefox(options=options)
                
                # Record process ID if possible to ensure cleanup
                try:
                    if hasattr(driver.service, 'process') and driver.service.process:
                        process_pid = driver.service.process.pid
                        logger.debug(f"Browser process ID: {process_pid}")
                except Exception:
                    pass
                
                # Set stricter timeouts to prevent hanging
                driver.set_page_load_timeout(15)     # 15 seconds page load timeout
                driver.set_script_timeout(8)         # 8 seconds script timeout
                
                # Navigate to URL
                logger.info(f"Navigating to {url}")
                
                try:
                    # Attempt navigation with minimal blocking
                    driver.get(url)
                except Exception as e:
                    # If timeout occurs, try to capture what's already loaded
                    logger.warning(f"Navigation timeout for {url}, attempting to capture partial page: {e}")
                
                # Wait a short time for essential content to render
                time.sleep(1.5)
                
                # Execute JavaScript to stop further resource loading
                try:
                    driver.execute_script("""
                    // Stop all image, CSS, and font loading
                    window.stop();
                    
                    // Remove all animations
                    var sheets = document.styleSheets;
                    for(var i = 0; i < sheets.length; i++) {
                        try {
                            if(sheets[i].cssRules) {
                                for(var j = 0; j < sheets[i].cssRules.length; j++) {
                                    var rule = sheets[i].cssRules[j];
                                    if(rule.cssText.includes('animation') || rule.cssText.includes('transition')) {
                                        sheets[i].deleteRule(j);
                                        j--;
                                    }
                                }
                            }
                        } catch(e) {}
                    }
                    """)
                except Exception:
                    pass
                
                # Ensure output directory exists
                dir_path = os.path.dirname(output_path)
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path, exist_ok=True)
                
                # Take screenshot
                driver.save_screenshot(output_path)
                logger.info(f"Screenshot saved to {output_path}")
                
                # Save minimal page content - only essentials like title and meta tags
                try:
                    text_path = output_path.rsplit('.', 1)[0] + '.txt'
                    with open(text_path, 'w', encoding='utf-8') as f:
                        try:
                            # Extract only the essentials
                            title = driver.title
                            current_url = driver.current_url
                            
                            # Get meta description if exists
                            meta_desc = ""
                            try:
                                meta_elements = driver.find_elements(By.XPATH, "//meta[@name='description']")
                                if meta_elements:
                                    meta_desc = meta_elements[0].get_attribute("content")
                            except Exception:
                                pass
                                
                            # Write minimal content
                            f.write(f"Title: {title}\n")
                            f.write(f"URL: {current_url}\n")
                            if meta_desc:
                                f.write(f"Description: {meta_desc}\n")
                        except Exception:
                            # If extraction fails, save full page source as fallback
                            f.write(driver.page_source)
                except Exception as e:
                    logger.warning(f"Failed to save page text: {e}")
                
                success = True
                break
            except Exception as e:
                logger.warning(f"Browser config {browser_config.get('name')} failed: {e}")
                if driver:
                    try:
                        driver.quit()
                    except Exception as qe:
                        logger.warning(f"Failed to quit driver: {qe}")
                    driver = None
        
        if not success:
            logger.error(f"All browser configurations failed for {url}")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"Screenshot failed: {e}")
        return False
    finally:
        # Ensure driver is properly closed
        if driver:
            try:
                driver.quit()
                logger.debug(f"Browser driver closed successfully for {url}")
            except Exception as e:
                logger.warning(f"Error closing browser driver: {e}")
        
        # Try to kill the process directly if we have the PID
        if process_pid:
            try:
                import signal
                import os
                try:
                    os.kill(process_pid, signal.SIGTERM)
                    logger.debug(f"Sent SIGTERM to browser process {process_pid}")
                    # Give it a moment to terminate gracefully
                    time.sleep(0.5)
                    
                    # Check if process still exists
                    try:
                        os.kill(process_pid, 0)
                        # If we get here, process is still running, try SIGKILL
                        os.kill(process_pid, signal.SIGKILL)
                        logger.debug(f"Sent SIGKILL to browser process {process_pid}")
                    except OSError:
                        # Process no longer exists, which is what we want
                        pass
                except Exception as ke:
                    logger.warning(f"Error killing browser process {process_pid}: {ke}")
            except Exception as e:
                logger.warning(f"Error during process cleanup: {e}")
        
        # Clean up temporary directories
        try:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
                logger.debug(f"Removed temporary directory {temp_dir}")
        except Exception as e:
            logger.warning(f"Failed to clean up temp dir: {e}")
        
        # Release semaphore
        _browser_semaphore.release()

def get_browser_configs(temp_dir):
    """Get a list of browser configurations to try in order"""
    configs = []
    
    # Find Chrome and Firefox binaries
    chrome_binary = find_chrome_binary('chrome')
    firefox_binary = find_firefox_binary('firefox')
    
    # Configuration 1: Chrome Ultra-minimal headless
    if chrome_binary:
        options1 = ChromeOptions()
        options1.add_argument("--headless=new")
        options1.add_argument("--no-sandbox")
        options1.add_argument("--disable-dev-shm-usage")
        options1.add_argument("--disable-gpu")
        options1.add_argument(f"--user-data-dir={temp_dir}")
        
        # Disable all extensions and unnecessary features
        options1.add_argument("--disable-extensions")
        options1.add_argument("--disable-plugins")
        options1.add_argument("--disable-software-rasterizer")
        options1.add_argument("--disable-popup-blocking")
        options1.add_argument("--disable-default-apps")
        options1.add_argument("--disable-background-networking")
        options1.add_argument("--disable-background-timer-throttling")
        options1.add_argument("--disable-backgrounding-occluded-windows")
        options1.add_argument("--disable-breakpad")
        options1.add_argument("--disable-client-side-phishing-detection")
        options1.add_argument("--disable-component-update")
        options1.add_argument("--disable-domain-reliability")
        options1.add_argument("--disable-features=TranslateUI,BlinkGenPropertyTrees,LazyFrameLoading,AutomationControlled")
        options1.add_argument("--disable-hang-monitor")
        options1.add_argument("--disable-ipc-flooding-protection")
        options1.add_argument("--disable-notifications")
        options1.add_argument("--disable-offer-store-unmasked-wallet-cards")
        options1.add_argument("--disable-print-preview")
        options1.add_argument("--disable-prompt-on-repost")
        options1.add_argument("--disable-renderer-backgrounding")
        options1.add_argument("--disable-sync")
        options1.add_argument("--mute-audio")
        options1.add_argument("--no-pings")
        options1.add_argument("--no-experiments")
        options1.add_argument("--no-first-run")
        options1.add_argument("--no-default-browser-check")
        
        # Limit memory usage
        options1.add_argument("--js-flags=--max-old-space-size=256")
        options1.add_argument("--memory-pressure-off")
        options1.add_argument("--force-fieldtrials=*BackgroundTracing/default/")
        
        options1.binary_location = chrome_binary
        configs.append({
            'name': 'chrome-ultra-minimal-headless',
            'options': options1,
            'binary': chrome_binary,
            'type': 'chrome'
        })
    
    # Configuration 2: Firefox Headless
    if firefox_binary:
        options2 = FirefoxOptions()
        options2.add_argument("--headless")
        options2.add_argument("--width=1280")
        options2.add_argument("--height=800")
        
        # Minimize memory usage
        options2.set_preference("browser.cache.disk.enable", False)
        options2.set_preference("browser.cache.memory.enable", False)
        options2.set_preference("browser.cache.offline.enable", False)
        options2.set_preference("browser.sessionhistory.max_entries", 1)
        options2.set_preference("browser.sessionhistory.max_total_viewers", 0)
        options2.set_preference("network.http.use-cache", False)
        options2.set_preference("browser.sessionstore.interval", 999999999)
        options2.set_preference("content.notify.interval", 999999999)
        options2.set_preference("browser.tabs.remote.autostart", False)
        options2.set_preference("browser.tabs.remote.autostart.2", False)
        
        options2.binary = firefox_binary
        configs.append({
            'name': 'firefox-headless',
            'options': options2,
            'binary': firefox_binary,
            'type': 'firefox'
        })
    
    # Configuration 3: Chrome Incognito mode with minimal features
    if chrome_binary:
        options3 = ChromeOptions()
        options3.add_argument("--incognito")
        options3.add_argument("--headless=new")
        options3.add_argument("--no-sandbox")
        options3.add_argument("--disable-dev-shm-usage")
        options3.add_argument(f"--user-data-dir={temp_dir}_2")
        
        # Disable all extensions and unnecessary features
        options3.add_argument("--disable-extensions")
        options3.add_argument("--disable-plugins")
        options3.add_argument("--disable-software-rasterizer")
        options3.add_argument("--disable-popup-blocking")
        options3.add_argument("--disable-default-apps")
        options3.add_argument("--disable-background-networking")
        options3.add_argument("--disable-component-update")
        options3.add_argument("--disable-domain-reliability")
        options3.add_argument("--mute-audio")
        options3.add_argument("--no-first-run")
        
        # Limit memory usage
        options3.add_argument("--js-flags=--max-old-space-size=256")
        
        options3.binary_location = chrome_binary
        configs.append({
            'name': 'chrome-minimal-incognito',
            'options': options3,
            'binary': chrome_binary,
            'type': 'chrome'
        })
    
    # Configuration 4: Firefox Private mode
    if firefox_binary:
        options4 = FirefoxOptions()
        options4.add_argument("--private")
        options4.add_argument("--headless")
        options4.add_argument("--width=800")
        options4.add_argument("--height=600")
        options4.binary = firefox_binary
        configs.append({
            'name': 'firefox-private',
            'options': options4,
            'binary': firefox_binary,
            'type': 'firefox'
        })
    
    # Shuffle configurations to avoid all workers trying the same config
    # This distributes the load better across different browser modes
    random.shuffle(configs)
    
    return configs

def find_chrome_binary(binary_name='chrome'):
    """Find Chrome or related binary on the system
    
    Args:
        binary_name: Name of the binary to find (chrome, chromedriver)
    
    Returns:
        str: Path to the binary or None if not found
    """
    possible_paths = []
    
    if binary_name == 'chrome':
        possible_paths = [
            "/usr/bin/chromium-browser",  # Ubuntu/Debian with snap
            "/usr/bin/chromium",          # Some Linux distros
            "/snap/bin/chromium",         # Snap installation
            "/usr/bin/google-chrome",     # Standard Chrome Linux
            "/usr/bin/google-chrome-stable",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",  # macOS
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",    # Windows
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
        ]
    elif binary_name == 'chromedriver':
        possible_paths = [
            "/usr/bin/chromedriver",
            "/usr/local/bin/chromedriver",
            "/snap/bin/chromedriver",
            "/home/linuxbrew/.linuxbrew/bin/chromedriver"
        ]
    
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            logger.info(f"Found {binary_name} binary at {path}")
            return path
            
    logger.warning(f"Could not find {binary_name} binary")
    return None

def find_firefox_binary(binary_name='firefox'):
    """Find Firefox or related binary on the system
    
    Args:
        binary_name: Name of the binary to find (firefox, geckodriver)
    
    Returns:
        str: Path to the binary or None if not found
    """
    possible_paths = []
    
    if binary_name == 'firefox':
        possible_paths = [
            "/usr/bin/firefox",           # Standard Linux
            "/snap/bin/firefox",          # Snap installation
            "/usr/lib/firefox/firefox",   # Some Linux distros
            "/usr/bin/firefox-esr",       # Debian ESR
            "/Applications/Firefox.app/Contents/MacOS/firefox", # macOS
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe",  # Windows
            "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe"
        ]
    elif binary_name == 'geckodriver':
        possible_paths = [
            "/usr/bin/geckodriver",
            "/usr/local/bin/geckodriver",
            "/snap/bin/geckodriver",
            "/home/linuxbrew/.linuxbrew/bin/geckodriver"
        ]
    
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            logger.info(f"Found {binary_name} binary at {path}")
            return path
            
    logger.warning(f"Could not find {binary_name} binary")
    return None

def filter_screenshot_tasks(findings):
    """Filter findings to identify unique screenshots needed"""
    # Keep track of unique URLs needing screenshots
    seen_urls = set()
    unique_findings = []
    
    for finding in findings:
        if finding is None:
            continue
        url = finding.get('url', '')
        
        # Skip items marked as downloadable
        if finding.get('downloadable'):
            continue
            
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique_findings.append(finding)
            finding['screenshot_duplicate_of'] = None
        else:
            # Mark as duplicate
            finding['screenshot_duplicate_of'] = url
    
    return unique_findings

def take_screenshots_parallel(task_list, max_workers=3):
    """Take screenshots sequentially with priority-based processing
    
    This version:
    1. Prioritizes important screenshots first
    2. Takes screenshots one at a time to reduce resource usage
    3. Cleans up the browser after each screenshot
    """
    # Initialize the screenshot system
    initialize_screenshot_system(max_workers=1)  # Set to 1 since we're processing sequentially
    
    # If task list is empty, nothing to do
    if not task_list:
        return
        
    logger.info(f"Taking {len(task_list)} screenshots sequentially")
    
    # Process high priority screenshots first
    high_priority_tasks = [task for task in task_list 
                          if task.get('priority', 'normal') == 'high']
    normal_priority_tasks = [task for task in task_list 
                            if task.get('priority', 'normal') == 'normal']
    low_priority_tasks = [task for task in task_list 
                         if task.get('priority', 'normal') == 'low']
    
    # Process in batches by priority
    all_batches = [
        ("high priority", high_priority_tasks),
        ("normal priority", normal_priority_tasks),
        ("low priority", low_priority_tasks)
    ]
    
    total_completed = 0
    total_tasks = len(task_list)
    
    for batch_idx, (batch_name, batch_tasks) in enumerate(all_batches):
        if not batch_tasks:
            continue
            
        logger.info(f"Processing {len(batch_tasks)} {batch_name} screenshots")
        
        # Aggressive cleanup before each priority batch
        clean_browser_environment()
        
        # Process each task in this batch sequentially
        batch_completed = 0
        
        for task in batch_tasks:
            try:
                # Take screenshot for this URL
                logger.info(f"Taking screenshot for {task['url']}")
                success = take_screenshot(
                    task['url'], 
                    task['output_path'],
                    task.get('priority', 'normal')
                )
                
                # Log result
                if success:
                    logger.info(f"✓ Screenshot for {task['url']}")
                else:
                    logger.warning(f"✗ Failed screenshot for {task['url']}")
                    
                # Clean up after each screenshot
                clean_browser_environment()
                
                # Update progress
                batch_completed += 1
                total_completed += 1
                
                if batch_completed % 5 == 0 or batch_completed == len(batch_tasks):
                    logger.info(f"Batch progress: {batch_completed}/{len(batch_tasks)}")
                
                if total_completed % 10 == 0 or total_completed == total_tasks:
                    logger.info(f"Overall progress: {total_completed}/{total_tasks}")
                    
                # Small delay between screenshots to ensure complete cleanup
                time.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error in screenshot task for {task['url']}: {e}")
                
        # Thorough cleanup after each batch
        clean_browser_environment()
        
    # Final cleanup after all screenshots
    logger.info("Screenshot tasks completed, performing final cleanup")
    clean_browser_environment()

# For testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Test URL
    test_url = "https://www.example.com"
    output_dir = "test_screenshots"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "test_screenshot.png")
    
    # Initialize screenshot system
    initialize_screenshot_system(max_workers=1)
    
    # Take screenshot
    success = take_screenshot(test_url, output_path, priority="high")
    print(f"Screenshot {'succeeded' if success else 'failed'}: {output_path}")

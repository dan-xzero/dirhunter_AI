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
import subprocess
import signal
import atexit
import glob
from typing import Dict, List, Any, Optional, Tuple
import urllib3

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logger = logging.getLogger(__name__)

# Register aggressive cleanup to run on script exit
def _aggressive_browser_cleanup():
    try:
        # Force kill ALL browser processes with SIGKILL
        subprocess.run(
            "pkill -9 -f 'firefox|firefox-bin|chrome|chromium|geckodriver|chromedriver|Xvfb'",
            shell=True, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass

# Register the cleanup function to run when the script exits
atexit.register(_aggressive_browser_cleanup)

# Import resource manager
try:
    from utils.resource_manager import resource_manager
except ImportError:
    resource_manager = None
    logger.warning("Resource manager not available - using default settings")

# Check for selenium availability
_SELENIUM_AVAILABLE = False
_WEBDRIVER_MANAGER_AVAILABLE = False
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
    
    # Add webdriver_manager for automatic driver download
    try:
        from webdriver_manager.chrome import ChromeDriverManager
        from webdriver_manager.firefox import GeckoDriverManager
        _WEBDRIVER_MANAGER_AVAILABLE = True
        logger.info("WebDriver Manager available - will auto-download drivers if needed")
    except ImportError:
        _WEBDRIVER_MANAGER_AVAILABLE = False
        logger.warning("WebDriver Manager not available - install with 'pip install webdriver-manager' for automatic driver download")
except ImportError:
    logger.warning("Selenium not installed - will use fallback screenshot methods")

# Detect whether pure_screenshot is available

# Default concurrency - will be updated by initialize_screenshot_system
_MAX_WORKERS = 1
_browser_semaphore = threading.Semaphore(1)

# Browser process timeout
_BROWSER_PROCESS_TIMEOUT = 30  # seconds

# Add global variable to track the best screenshot method
_BEST_SCREENSHOT_METHOD = None
_FIRST_URL_PROCESSED = False

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
    """Clean up browser environment before starting - aggressive version"""
    logger.info("Performing aggressive browser cleanup...")
    
    try:
        # First try standard cleanup if resource_manager is available
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
                logger.error(f"Error during standard browser cleanup: {e}")
        
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
        
        # Give the system a moment to clean up processes
        time.sleep(1)
        
        # Clean up any stale lock files
        for lock_file in glob.glob("/tmp/.X*-lock"):
            try:
                os.remove(lock_file)
                logger.debug(f"Removed stale lock file: {lock_file}")
            except Exception:
                pass
                
        # Always clean temp dirs by pattern
        try:
            temp_dir = tempfile.gettempdir()
            browser_patterns = ['chrome_', 'firefox_', 'gecko_', 'tmp_', '.org.chromium.', '.com.google.']
            for item in os.listdir(temp_dir):
                if any(pattern in item for pattern in browser_patterns) and os.path.isdir(os.path.join(temp_dir, item)):
                    try:
                        shutil.rmtree(os.path.join(temp_dir, item), ignore_errors=True)
                    except Exception as e:
                        logger.warning(f"Failed to remove temp dir {os.path.join(temp_dir, item)}: {e}")
        except Exception as e:
            logger.error(f"Error cleaning temporary directories: {e}")
            
        # Count processes after cleanup
        count_cmd = "ps aux | grep -E 'firefox|chrome|chromium|gecko|selenium|xvfb' | grep -v grep | wc -l"
        result = subprocess.run(count_cmd, shell=True, text=True, capture_output=True)
        remaining = int(result.stdout.strip())
        if remaining > 0:
            logger.warning(f"Browser cleanup detected {remaining} remaining processes")
        else:
            logger.info("All browser processes successfully terminated")
            
    except Exception as e:
        logger.error(f"Error during aggressive browser cleanup: {e}")

def create_fallback_screenshot(url, output_path):
    """
    Creates a fallback screenshot file with basic info for URLs that couldn't be screenshotted
    """
    import os
    import time
    import logging
    import requests
    from datetime import datetime
    from PIL import Image, ImageDraw, ImageFont
    import re
    import textwrap
    
    logger = logging.getLogger(__name__)
    
    try:
        # Default values
        status = "Unknown"
        title = "Unavailable"
        content = "Could not fetch content"
        
        # Try to fetch content if possible
        try:
            response = requests.get(url, timeout=10, verify=False)
            status = f"{response.status_code}"
            content = response.text[:500] + "..." if len(response.text) > 500 else response.text
            
            # Try to extract title
            title_match = re.search("<title>(.*?)</title>", response.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()[:100]
                
        except Exception as e:
            logger.error(f"Failed to fetch URL content: {str(e)}")
        
        # Create a basic image
        width, height = 1024, 768
        image = Image.new("RGB", (width, height), color="#FFFFFF")
        draw = ImageDraw.Draw(image)
        
        # Draw elements
        draw.rectangle([(0, 0), (width, 60)], fill="#F0F0F0")
        draw.text((20, 20), f"URL: {url}", fill="#000000")
        draw.text((20, 80), f"Status: {status}", fill="#000000")
        draw.text((20, 110), f"Title: {title}", fill="#000000")
        draw.line([(20, 140), (width-20, 140)], fill="#CCCCCC", width=1)
        
        # Add content preview
        y_pos = 160
        for line in textwrap.wrap(content, width=120):
            draw.text((20, y_pos), line, fill="#333333")
            y_pos += 20
            if y_pos > height - 40:
                draw.text((20, y_pos), "...", fill="#333333")
                break
                
        # Add timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        draw.text((20, height-30), f"Fallback screenshot created: {timestamp}", fill="#999999")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save the image
        image.save(output_path)
        logger.info(f"Created fallback screenshot for {url}")
        return True
    
    except Exception as e:
        logger.error(f"Fallback screenshot failed: {str(e)}")
        return False

def take_direct_screenshot(url, output_path):
    """Take a screenshot using direct browser command
    
    This method bypasses Selenium and directly uses Chrome/Chromium
    with Xvfb for more reliable screenshots in restricted environments.
    
    Args:
        url: URL to capture
        output_path: Path to save the screenshot
    
    Returns:
        bool: True if successful, False otherwise
    """
    logger.info(f"Taking direct screenshot of {url}")
    
    # Ensure output directory exists
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create output directory: {e}")
        return False
    
    # Check if Xvfb is available
    xvfb_available = False
    try:
        result = subprocess.run(['which', 'Xvfb'], capture_output=True, text=True)
        if result.returncode == 0:
            xvfb_available = True
        else:
            logger.warning("Xvfb not found - will try alternative approach")
    except Exception:
        pass
        
    # Try headless Chrome directly without Xvfb if not available
    if not xvfb_available:
        chrome_binary = find_chrome_binary('chrome')
        if not chrome_binary:
            logger.error("Chrome not found for direct screenshot")
            return False
            
        try:
            # Create a temporary script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as script:
                script_path = script.name
                script.write(f"""#!/bin/bash
export DBUS_SESSION_BUS_ADDRESS="unix:path=/dev/null"

# Take screenshot with --headless flag
"{chrome_binary}" --headless=new --disable-gpu --no-sandbox \\
    --disable-dev-shm-usage --disable-software-rasterizer \\
    --disable-background-networking --disable-default-apps \\
    --disable-extensions --disable-sync --disable-translate \\
    --hide-scrollbars --metrics-recording-only --mute-audio \\
    --no-first-run --safebrowsing-disable-auto-update \\
    --screenshot="{output_path}" "{url}" 

# Save page content
"{chrome_binary}" --headless=new --disable-gpu --no-sandbox \\
    --disable-extensions --disable-dev-shm-usage \\
    --dump-dom "{url}" > "{os.path.splitext(output_path)[0]}.txt" 2>/dev/null
""")
            
            # Make script executable
            os.chmod(script_path, 0o755)
            
            # Run the script
            result = subprocess.run([script_path], 
                                    capture_output=True, 
                                    text=True, 
                                    timeout=60)
            
            # Check if screenshot was created
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                logger.info(f"Direct screenshot saved to {output_path}")
                return True
            else:
                logger.error(f"Direct screenshot failed: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error taking direct screenshot without Xvfb: {e}")
            return False
        finally:
            # Clean up the script
            try:
                os.unlink(script_path)
            except Exception:
                pass
    
    # Find an available display number
    display_num = 99
    while os.path.exists(f"/tmp/.X{display_num}-lock"):
        display_num += 1
    
    logger.info(f"Using display :{display_num}")
    
    # Create a temporary script to run the screenshot
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as script:
        script_path = script.name
        script.write(f"""#!/bin/bash
# Start Xvfb
Xvfb :{display_num} -screen 0 1280x1024x24 -ac &
XVFB_PID=$!

# Wait for Xvfb
sleep 1

# Set display and prevent dbus errors
export DISPLAY=:{display_num}
export DBUS_SESSION_BUS_ADDRESS="unix:path=/dev/null"

# Take screenshot
BROWSER=""
if [ -x "/usr/bin/google-chrome-stable" ]; then
    BROWSER="/usr/bin/google-chrome-stable"
elif [ -x "/usr/bin/google-chrome" ]; then
    BROWSER="/usr/bin/google-chrome"
elif [ -x "/usr/bin/chromium-browser" ]; then
    BROWSER="/usr/bin/chromium-browser"
elif [ -x "/usr/bin/chromium" ]; then
    BROWSER="/usr/bin/chromium"
fi

if [ -n "$BROWSER" ]; then
    $BROWSER --headless=new --disable-gpu --no-sandbox \\
        --disable-dev-shm-usage --disable-software-rasterizer \\
        --disable-background-networking --disable-default-apps \\
        --disable-extensions --disable-sync --disable-translate \\
        --hide-scrollbars --metrics-recording-only --mute-audio \\
        --no-first-run --safebrowsing-disable-auto-update \\
        --screenshot="{output_path}" "{url}" 
    
    # Save page content
    $BROWSER --headless=new --disable-gpu --no-sandbox \\
        --disable-extensions --disable-dev-shm-usage \\
        --dump-dom "{url}" > "{os.path.splitext(output_path)[0]}.txt" 2>/dev/null
fi

# Kill Xvfb
kill $XVFB_PID 2>/dev/null || true
""")
    
    # Make script executable
    os.chmod(script_path, 0o755)
    
    try:
        # Run the script
        result = subprocess.run([script_path], 
                                capture_output=True, 
                                text=True, 
                                timeout=60)
        
        # Check if screenshot was created
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            logger.info(f"Direct screenshot saved to {output_path}")
            return True
        else:
            logger.error(f"Direct screenshot failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error taking direct screenshot: {e}")
        return False
    finally:
        # Clean up the script
        try:
            os.unlink(script_path)
        except Exception:
            pass
        
def take_screenshot(url, output_path, priority="normal"):
    """Take a screenshot of a URL with robust tiered strategy selection
    
    Implements a multi-tiered fallback approach:
    1. Direct browser command (most reliable in restricted environments)
    2. Browser screenshot with multiple configurations 
    3. Resource-aware Selenium approach (adjusts parallelism based on system)
    4. Fallback image generation as last resort
    
    Args:
        url: The URL to capture
        output_path: Where to save the screenshot
        priority: Priority level ('high', 'normal', 'low')
    
    Returns:
        bool: True if successful, False otherwise
    """
    global _BEST_SCREENSHOT_METHOD, _FIRST_URL_PROCESSED
    import os
    
    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir:
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create output directory '{output_dir}': {e}")
            return False
    
    logger.info(f"Taking screenshot of {url} with {priority} priority")
    
    # For the first URL, try all tiers to determine the best method
    if not _FIRST_URL_PROCESSED:
        logger.info(f"First URL: Determining optimal screenshot method for {url}")
        _FIRST_URL_PROCESSED = True
        
        # Tier 1: Direct screenshot method (most reliable in many environments)
        logger.info(f"Tier 1: Trying direct browser command method")
        success = take_direct_screenshot(url, output_path)
        if success:
            _BEST_SCREENSHOT_METHOD = "direct"
            logger.info(f"✓ Direct browser command method successful - will use for subsequent URLs")
            return True
        
        # Tier 2: If direct method fails, try browser screenshot with multiple configs
        logger.info(f"Tier 1 failed, trying Tier 2: Browser with multiple configurations for {url}")
        success = take_browser_screenshot(url, output_path)
        if success:
            _BEST_SCREENSHOT_METHOD = "browser"
            logger.info(f"✓ Browser configurations method successful - will use for subsequent URLs")
            return True
        
        # Tier 3: If browser configs fail, try resource-aware Selenium approach
        logger.info(f"Tier 2 failed, trying Tier 3: Resource-aware Selenium approach for {url}")
        success = take_resource_aware_screenshot(url, output_path)
        if success:
            _BEST_SCREENSHOT_METHOD = "resource-aware"
            logger.info(f"✓ Resource-aware Selenium method successful - will use for subsequent URLs")
            return True
        
        # Tier 4: If all browser methods fail, use fallback image generation
        logger.info(f"Tier 3 failed, using Tier 4: Fallback image generation for {url}")
        success = create_fallback_screenshot(url, output_path)
        if success:
            _BEST_SCREENSHOT_METHOD = "fallback"
            logger.info(f"✓ Fallback image generation successful - will use for subsequent URLs")
            return True
            
        # If everything failed, we have no best method
        logger.error(f"All screenshot methods failed for {url}")
        _BEST_SCREENSHOT_METHOD = "fallback"  # Default to fallback as last resort
        return False
    
    # For subsequent URLs, use the best method determined from the first URL
    logger.info(f"Using previously determined optimal method ({_BEST_SCREENSHOT_METHOD}) for {url}")
    
    success = False
    if _BEST_SCREENSHOT_METHOD == "direct":
        success = take_direct_screenshot(url, output_path)
    elif _BEST_SCREENSHOT_METHOD == "browser":
        success = take_browser_screenshot(url, output_path)
    elif _BEST_SCREENSHOT_METHOD == "resource-aware":
        success = take_resource_aware_screenshot(url, output_path)
    else:  # fallback
        success = create_fallback_screenshot(url, output_path)
        
    # If the chosen method fails, try fallbacks
    if not success:
        logger.warning(f"Preferred method {_BEST_SCREENSHOT_METHOD} failed, trying fallbacks for {url}")
        
        # Try remaining methods in order
        if _BEST_SCREENSHOT_METHOD == "direct":
            logger.info(f"Trying browser configurations for {url}")
            success = take_browser_screenshot(url, output_path)
            if not success:
                logger.info(f"Trying resource-aware Selenium for {url}")
                success = take_resource_aware_screenshot(url, output_path)
                if not success:
                    logger.info(f"Trying fallback image for {url}")
                    success = create_fallback_screenshot(url, output_path)
        elif _BEST_SCREENSHOT_METHOD == "browser":
            logger.info(f"Trying resource-aware Selenium for {url}")
            success = take_resource_aware_screenshot(url, output_path)
            if not success:
                logger.info(f"Trying fallback image for {url}")
                success = create_fallback_screenshot(url, output_path)
        elif _BEST_SCREENSHOT_METHOD == "resource-aware":
            logger.info(f"Trying fallback image for {url}")
            success = create_fallback_screenshot(url, output_path)
    
    return success

def take_resource_aware_screenshot(url, output_path, minimal_mode=False, ultra_minimal_mode=False):
    """Take a screenshot with resource-aware settings
    
    Args:
        url: URL to screenshot
        output_path: Path to save screenshot
        minimal_mode: Use minimal browser settings (less memory/CPU)
        ultra_minimal_mode: Use ultra-minimal settings (for low resources)
        
    Returns:
        bool: True if successful
    """
    if not _SELENIUM_AVAILABLE:
        logger.warning("Cannot take resource-aware screenshot, Selenium not available")
        return False
        
    success = False
    driver = None
    process_pid = None
    browser_type = None
    
    try:
        # Create a unique temporary directory for browser user data
        temp_dir = os.path.join(tempfile.gettempdir(), f"browser_{uuid.uuid4().hex}")
        os.makedirs(temp_dir, exist_ok=True)
        
        # Get browser configurations with resource-aware options
        browser_configs = get_browser_configs(temp_dir)
        
        # If in minimal mode, modify the configurations to use less resources
        if minimal_mode or ultra_minimal_mode:
            minimal_configs = []
            for config in browser_configs:
                if config.get('type') == 'chrome':
                    options = config.get('options')
                    # Add more aggressive memory-saving options
                    options.add_argument('--js-flags=--expose-gc')
                    options.add_argument('--single-process')
                    options.add_argument('--disable-application-cache')
                    options.add_argument('--disable-dev-shm-usage')
                    options.add_argument('--disable-accelerated-2d-canvas')
                    options.add_argument('--disable-web-security')
                    options.add_argument('--disk-cache-size=1')
                    
                    # Ultra minimal mode disables even more features
                    if ultra_minimal_mode:
                        options.add_argument('--disable-features=TranslateUI,BlinkGenPropertyTrees')
                        options.add_argument('--disable-extensions')
                        options.add_argument('--disable-component-extensions-with-background-pages')
                        options.add_argument('--disable-background-networking')
                        options.add_argument('--disable-component-update')
                        options.add_argument('--disable-domain-reliability')
                        options.add_argument('--disable-backgrounding-occluded-windows')
                    
                    minimal_configs.append(config)
                    
                elif config.get('type') == 'firefox' and len(minimal_configs) < 1:
                    # Only include Firefox in minimal mode if we have no Chrome config
                    options = config.get('options')
                    # Add memory settings for Firefox
                    options.set_preference('browser.cache.disk.enable', False)
                    options.set_preference('browser.cache.memory.enable', False)
                    minimal_configs.append(config)
            
            # Replace configs with minimal subset
            browser_configs = minimal_configs if minimal_configs else browser_configs[:1]
        
        # Try browser configurations
        for browser_config in browser_configs:
            try:
                # Get browser type and options
                browser_type = browser_config.get('type', 'chrome')
                options = browser_config.get('options')
                
                # Setup driver with timeout
                logger.info(f"Initializing resource-aware {browser_type} for {url}")
                
                if browser_type == 'chrome':
                    # Try to find chromedriver
                    driver_path = find_chrome_binary('chromedriver')
                    if driver_path:
                        service = ChromeService(executable_path=driver_path)
                        driver = webdriver.Chrome(service=service, options=options)
                    else:
                        # Use webdriver_manager if available
                        if _WEBDRIVER_MANAGER_AVAILABLE:
                            try:
                                from webdriver_manager.chrome import ChromeDriverManager
                                service = ChromeService(ChromeDriverManager().install())
                                driver = webdriver.Chrome(service=service, options=options)
                            except Exception as e:
                                logger.warning(f"WebDriver manager failed: {e}")
                                # Let Selenium try to find the driver
                                driver = webdriver.Chrome(options=options)
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
                        # Use webdriver_manager if available
                        if _WEBDRIVER_MANAGER_AVAILABLE:
                            try:
                                from webdriver_manager.firefox import GeckoDriverManager
                                service = FirefoxService(GeckoDriverManager().install())
                                driver = webdriver.Firefox(service=service, options=options)
                            except Exception as e:
                                logger.warning(f"WebDriver manager failed: {e}")
                                # Let Selenium try to find the driver
                                driver = webdriver.Firefox(options=options)
                        else:
                            # Let Selenium try to find the driver
                            driver = webdriver.Firefox(options=options)
                
                # Record process ID for cleanup
                try:
                    if hasattr(driver.service, 'process') and driver.service.process:
                        process_pid = driver.service.process.pid
                except Exception:
                    pass
                
                # Use very minimal settings for resource-constrained environments
                driver.set_page_load_timeout(15)  # Shorter timeout
                
                # Navigate with reduced wait time in minimal modes
                logger.info(f"Navigating to {url} with resource-aware settings")
                try:
                    driver.get(url)
                except Exception as e:
                    logger.warning(f"Navigation timeout in resource-aware mode: {e}")
                
                # Shorter wait time in minimal modes
                time_to_wait = 0.5 if ultra_minimal_mode else 1.0
                time.sleep(time_to_wait)
                
                # Stop all resource loading immediately in ultra minimal mode
                if ultra_minimal_mode:
                    try:
                        driver.execute_script("window.stop();")
                    except Exception:
                        pass
                
                # Ensure output directory exists
                dir_path = os.path.dirname(output_path)
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path, exist_ok=True)
                
                # Take screenshot with minimal error handling
                try:
                    driver.save_screenshot(output_path)
                    logger.info(f"Resource-aware screenshot saved to {output_path}")
                    
                    # Minimal text extraction
                    try:
                        text_path = output_path.rsplit('.', 1)[0] + '.txt'
                        with open(text_path, 'w', encoding='utf-8') as f:
                            f.write(f"Title: {driver.title}\n")
                            f.write(f"URL: {driver.current_url}\n")
                    except Exception:
                        pass
                        
                    success = True
                    break
                except Exception as e:
                    logger.warning(f"Failed to save resource-aware screenshot: {e}")
            except Exception as e:
                logger.warning(f"Resource-aware browser config failed: {e}")
                
            # Clean up driver if created but failed
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass
                
        return success
    except Exception as e:
        logger.error(f"Resource-aware screenshot failed: {e}")
        return False
    finally:
        # Release semaphore
        _browser_semaphore.release()
        
        # Ensure driver is properly closed
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        
        # Try to kill the process directly if we have the PID
        if process_pid:
            try:
                try:
                    os.kill(process_pid, signal.SIGTERM)
                except Exception:
                    pass
            except Exception:
                pass
        
        # Clean up temporary directories
        try:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

def take_browser_screenshot(url, output_path):
    """Take a screenshot using a browser (Selenium) with minimal resource usage"""
    # Import os directly into this function's scope to ensure availability
    import os
    import signal
    import time
    import tempfile
    import uuid
    import shutil
    
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
                        # Use webdriver_manager if available
                        if _WEBDRIVER_MANAGER_AVAILABLE:
                            try:
                                from webdriver_manager.chrome import ChromeDriverManager
                                service = ChromeService(ChromeDriverManager().install())
                                driver = webdriver.Chrome(service=service, options=options)
                            except Exception as e:
                                logger.warning(f"WebDriver manager failed: {e}")
                                # Let Selenium try to find the driver
                                driver = webdriver.Chrome(options=options)
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
                        # Use webdriver_manager if available
                        if _WEBDRIVER_MANAGER_AVAILABLE:
                            try:
                                from webdriver_manager.firefox import GeckoDriverManager
                                service = FirefoxService(GeckoDriverManager().install())
                                driver = webdriver.Firefox(service=service, options=options)
                            except Exception as e:
                                logger.warning(f"WebDriver manager failed: {e}")
                                # Let Selenium try to find the driver
                                driver = webdriver.Firefox(options=options)
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
        
                dir_path = os.path.dirname(output_path)
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path, exist_ok=True)
        
                # Take screenshot
                try:
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
                    break  # Break out of the browser configurations loop
                except Exception as e:
                    logger.warning(f"Failed to save screenshot: {e}")
            except Exception as e:
                logger.warning(f"Browser config {browser_config.get('name')} failed: {e}")
                
            # Clean up driver if it was created but failed
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
        # Release the semaphore
        _browser_semaphore.release()
        
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
                # We already imported os and signal at the top of the function
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
            "/usr/bin/google-chrome-stable",  # Standard Chrome Linux
            "/usr/bin/google-chrome",         # Standard Chrome Linux
            "/usr/bin/chromium-browser",      # Ubuntu/Debian with snap
            "/usr/bin/chromium",              # Some Linux distros
            "/snap/bin/chromium",             # Snap installation
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",  # macOS
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",    # Windows
            "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
        ]
    elif binary_name == 'chromedriver':
        if _WEBDRIVER_MANAGER_AVAILABLE:
            try:
                from webdriver_manager.chrome import ChromeDriverManager
                return ChromeDriverManager().install()
            except Exception as e:
                logger.warning(f"ChromeDriverManager failed: {e}")
        
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
        if _WEBDRIVER_MANAGER_AVAILABLE:
            try:
                from webdriver_manager.firefox import GeckoDriverManager
                return GeckoDriverManager().install()
            except Exception as e:
                logger.warning(f"GeckoDriverManager failed: {e}")
        
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
    """Take screenshots of multiple URLs in parallel
    
    Args:
        task_list: List of (url, output_path, priority) tuples
        max_workers: Maximum number of concurrent workers
    
    Returns:
        dict: Results with URLs as keys and success status as values
    """
    global _FIRST_URL_PROCESSED, _BEST_SCREENSHOT_METHOD
    
    # Reset the best method for each batch
    _FIRST_URL_PROCESSED = False
    _BEST_SCREENSHOT_METHOD = None
    
    logger.info(f"Taking screenshots for {len(task_list)} URLs with {max_workers} workers")
    
    # Process the high priority URLs first
    task_list = sorted(task_list, key=lambda x: 0 if x[2] == "high" else 1)
    
    results = {}
    
    # Take screenshots sequentially to avoid resource issues
    for url, output_path, priority in task_list:
        try:
            success = take_screenshot(url, output_path, priority)
            results[url] = success
            logger.info(f"{'✓' if success else '✗'} Screenshot for {url}")
        except Exception as e:
            logger.error(f"Error taking screenshot for {url}: {e}")
            results[url] = False
    
    return results

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

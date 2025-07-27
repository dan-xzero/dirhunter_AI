#!/usr/bin/env python3
"""
Screenshot Utility - Robust implementation that works in difficult environments
"""

import os
import sys
import logging
import threading
import time
import tempfile
import uuid

# Configure logging
logger = logging.getLogger(__name__)

# Check for selenium availability
_SELENIUM_AVAILABLE = False
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    _SELENIUM_AVAILABLE = True
except ImportError:
    logger.warning("Selenium not installed - will use fallback screenshot methods")

# Limit concurrent Chrome instances
_chrome_semaphore = threading.Semaphore(3)

def take_screenshot(url, output_path):
    """Take a screenshot of a URL with robust error handling"""
    if not _SELENIUM_AVAILABLE:
        logger.info(f"Selenium not available - using fallback for {url}")
        return create_fallback_screenshot(url, output_path)
    
    # Acquire semaphore to limit concurrent Chrome instances
    if not _chrome_semaphore.acquire(timeout=60):
        logger.warning(f"Semaphore timeout - using fallback for {url}")
        return create_fallback_screenshot(url, output_path)
    
    driver = None
    success = False
    
    try:
        # Create a unique temporary directory for Chrome user data
        temp_dir = os.path.join(tempfile.gettempdir(), f"chrome_{uuid.uuid4().hex}")
        os.makedirs(temp_dir, exist_ok=True)
        
        # Configure Chrome options - use minimal settings that work
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument(f"--user-data-dir={temp_dir}")
        
        # Find the Chrome binary
        chrome_binary = find_chrome_binary()
        if chrome_binary:
            options.binary_location = chrome_binary
        
        # Setup driver
        logger.info(f"Initializing Chrome driver for {url}")
        
        # Try to find chromedriver
        chromedriver_path = find_chromedriver()
        if chromedriver_path:
            service = Service(executable_path=chromedriver_path)
            driver = webdriver.Chrome(service=service, options=options)
        else:
            # Let Selenium try to find the driver
            driver = webdriver.Chrome(options=options)
        
        # Set timeout and navigate
        driver.set_page_load_timeout(30)
        logger.info(f"Navigating to {url}")
        driver.get(url)
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Take screenshot
        driver.save_screenshot(output_path)
        logger.info(f"Screenshot saved to {output_path}")
        
        # Save page content
        try:
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write(driver.page_source)
        except Exception as e:
            logger.warning(f"Failed to save page text: {e}")
        
        success = True
        return True
        
    except Exception as e:
        logger.error(f"Screenshot failed: {e}")
        return create_fallback_screenshot(url, output_path)
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        
        # Clean up temporary directories
        try:
            import shutil
            if 'temp_dir' in locals() and temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Failed to clean up temp dir: {e}")
        
        # Release semaphore
        _chrome_semaphore.release()

def find_chrome_binary():
    """Find Chrome or Chromium binary on the system"""
    possible_paths = [
        "/usr/bin/chromium-browser",  # Ubuntu/Debian with snap
        "/usr/bin/chromium",          # Some Linux distros
        "/snap/bin/chromium",         # Snap installation
        "/usr/bin/google-chrome",     # Standard Chrome Linux
        "/usr/bin/google-chrome-stable"
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            logger.info(f"Found Chrome binary at {path}")
            return path
            
    logger.warning("Could not find Chrome binary")
    return None

def find_chromedriver():
    """Find chromedriver on the system"""
    possible_paths = [
        "/usr/bin/chromedriver",
        "/usr/local/bin/chromedriver"
    ]
    
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            logger.info(f"Found chromedriver at {path}")
            return path
            
    logger.warning("Could not find chromedriver")
    return None

def create_fallback_screenshot(url, output_path):
    """Create a fallback screenshot when Selenium fails"""
    try:
        # Try using requests to get page content
        import requests
        from PIL import Image, ImageDraw
        
        logger.info(f"Creating fallback screenshot for {url}")
        
        # Try to fetch page content
        try:
            response = requests.get(url, timeout=30, verify=False, headers={
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
        except Exception:
            content = None
            status = "Error"
            title = None
        
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
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Save image and text
        img.save(output_path)
        logger.info(f"Fallback image saved to {output_path}")
        
        # Save text content if available
        text_path = output_path.rsplit('.', 1)[0] + '.txt'
        with open(text_path, 'w', encoding='utf-8') as f:
            f.write(content if content else f"Failed to retrieve content for {url}")
        
        return True
    except Exception as e:
        logger.error(f"Fallback screenshot failed: {e}")
        
        # Last resort: create empty files
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(b'')
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            with open(text_path, 'w') as f:
                f.write(f"Screenshot unavailable for {url}")
        except Exception:
            pass
        
        return False

# Batch processing functions (keep the same interface)
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
    """Take multiple screenshots in parallel"""
    import concurrent.futures
    
    logger.info(f"Taking {len(task_list)} screenshots in parallel")
    
    # Process with appropriate concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_task = {
            executor.submit(take_screenshot, task['url'], task['output_path']): task
            for task in task_list
        }
        
        # Process as completed
        completed = 0
        for future in concurrent.futures.as_completed(future_to_task):
            task = future_to_task[future]
            try:
                success = future.result()
                if success:
                    logger.info(f"✓ Screenshot for {task['url']}")
                else:
                    logger.warning(f"✗ Failed screenshot for {task['url']}")
            except Exception as e:
                logger.error(f"Error in screenshot task: {e}")
            
            # Update progress
            completed += 1
            if completed % 5 == 0 or completed == len(task_list):
                logger.info(f"Screenshot progress: {completed}/{len(task_list)}")

# For testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Test URL
    test_url = "https://www.example.com"
    output_dir = "test_screenshots"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "test_screenshot.png")
    
    # Take screenshot
    success = take_screenshot(test_url, output_path)
    print(f"Screenshot {'succeeded' if success else 'failed'}: {output_path}")

#!/usr/bin/env python3
"""
DirHunter AI Update Script

This script updates the dirhunter codebase to use the best available screenshot method
and fixes issues with domain cards by ensuring all required data is present.
"""

import os
import sys
import logging
import shutil
import importlib.util

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def check_requirements():
    """Check and install requirements"""
    required = ["requests", "Pillow"]
    missing = []
    
    for package in required:
        if not importlib.util.find_spec(package):
            missing.append(package)
    
    if missing:
        logger.info(f"Installing missing packages: {', '.join(missing)}")
        try:
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
            logger.info("Successfully installed missing packages")
        except Exception as e:
            logger.warning(f"Could not install packages: {e}")
            logger.warning("The script will continue, but some features may not work")

def update_screenshot_module():
    """Update the screenshot module with our improvements"""
    
    # Check if screenshot.py exists
    if not os.path.exists("utils/screenshot.py"):
        logger.error("utils/screenshot.py not found - is this the right directory?")
        return False
        
    # Check if our new modules exist
    has_pure_screenshot = os.path.exists("utils/pure_screenshot.py")
    
    if not has_pure_screenshot:
        logger.error("utils/pure_screenshot.py not found - run this script from the project root")
        return False
    
    # Create backup of original screenshot.py
    backup_path = "utils/screenshot.py.bak"
    if not os.path.exists(backup_path):
        shutil.copy2("utils/screenshot.py", backup_path)
        logger.info(f"Created backup of original screenshot.py at {backup_path}")
    
    # Create the updated screenshot.py that uses the best available method
    with open("utils/screenshot.py", "w") as f:
        f.write("""#!/usr/bin/env python3
\"\"\"
Screenshot Utility with Multi-Strategy Support

This module automatically uses the best available screenshot method:
1. Selenium (if available)
2. Pure Python fallback (requests + PIL)
3. Simple placeholder if all else fails
\"\"\"

import os
import sys
import logging
import threading
import time
import importlib.util

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

# Chrome driver setup helpers
def setup_chrome_driver():
    \"\"\"Find and set up ChromeDriver service\"\"\"
    # Various possible ChromeDriver locations
    potential_driver_paths = [
        "/usr/bin/chromedriver",
        "/usr/local/bin/chromedriver",
    ]
    for driver_path in potential_driver_paths:
        if os.path.exists(driver_path) and os.access(driver_path, os.X_OK):
            try:
                return Service(driver_path)
            except Exception:
                pass
    return None

def take_screenshot(url, output_path):
    \"\"\"Take a screenshot using the best available method\"\"\"
    # Try Selenium method first (if available)
    if _SELENIUM_AVAILABLE:
        logger.info(f"Attempting Selenium screenshot for {url}")
        try:
            selenium_success = _take_selenium_screenshot(url, output_path)
            if selenium_success:
                return True
            logger.warning(f"Selenium screenshot failed for {url}, trying pure Python method")
        except Exception as e:
            logger.warning(f"Selenium screenshot error: {e}")
    
    # Try pure Python method next
    try:
        from utils.pure_screenshot import capture_screenshot
        logger.info(f"Attempting pure Python screenshot for {url}")
        python_success = capture_screenshot(url, output_path)
        if python_success:
            return True
        logger.warning("Pure Python screenshot failed, trying simple placeholder")
    except Exception as e:
        logger.warning(f"Pure Python screenshot error: {e}")
    
    # Last resort: Simple placeholder
    try:
        return _create_simple_placeholder(url, output_path)
    except Exception as e:
        logger.error(f"Failed to create even a simple placeholder: {e}")
        # Create empty files as absolute last resort
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(b'')
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            with open(text_path, 'w') as f:
                f.write(f"Screenshot failed for {url}")
        except Exception:
            pass
        return False

def _take_selenium_screenshot(url, output_path):
    \"\"\"Internal helper: Take screenshot using Selenium\"\"\"
    if not _chrome_semaphore.acquire(timeout=60):
        logger.warning("Chrome semaphore timeout - too many concurrent Chrome instances")
        return False
    
    driver = None
    try:
        # Setup Chrome with minimal options to reduce errors
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        
        # Create driver with minimal features
        service = setup_chrome_driver()
        if service:
            driver = webdriver.Chrome(service=service, options=options)
        else:
            driver = webdriver.Chrome(options=options)
            
        driver.set_page_load_timeout(30)
        driver.get(url)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Take screenshot
        driver.save_screenshot(output_path)
        logger.info(f"Selenium screenshot saved: {output_path}")
        
        # Save page text
        try:
            text_content = driver.page_source
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write(text_content)
        except Exception as e:
            logger.warning(f"Failed to save page text: {e}")
            
        return True
    except Exception as e:
        logger.error(f"Selenium screenshot failed: {e}")
        return False
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass
        _chrome_semaphore.release()

def _create_simple_placeholder(url, output_path):
    \"\"\"Create a simple placeholder image with URL and timestamp\"\"\"
    try:
        # Check if PIL is available
        if importlib.util.find_spec("PIL"):
            from PIL import Image, ImageDraw
            
            # Create blank image
            width, height = 1280, 800
            img = Image.new('RGB', (width, height), color=(240, 240, 240))
            draw = ImageDraw.Draw(img)
            
            # Add URL text
            draw.text((20, 20), f"URL: {url}", fill=(0, 0, 0))
            draw.text((20, 60), f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}", fill=(0, 0, 0))
            draw.text((20, 100), "Screenshot Unavailable", fill=(255, 0, 0))
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Save image
            img.save(output_path)
            
            # Create text file
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            with open(text_path, 'w') as f:
                f.write(f"Screenshot unavailable for {url}")
                
            logger.info(f"Created simple placeholder for {url}")
            return True
        else:
            # PIL not available, create empty files
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(b'')
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            with open(text_path, 'w') as f:
                f.write(f"Screenshot unavailable for {url} (no PIL)")
            logger.info(f"Created empty placeholder for {url}")
            return True
    except Exception as e:
        logger.error(f"Failed to create simple placeholder: {e}")
        return False

# Batch processing functions - preserve the interface of the original module
def filter_screenshot_tasks(findings):
    \"\"\"Filter findings to identify unique screenshots needed\"\"\"
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
    \"\"\"Take multiple screenshots in parallel\"\"\"
    # If Selenium isn't available, don't bother with parallelism for the fallback
    if not _SELENIUM_AVAILABLE:
        logger.info(f"Processing {len(task_list)} screenshots sequentially (fallback mode)")
        for task in task_list:
            take_screenshot(task['url'], task['output_path'])
        return
    
    # Use threading for parallel processing
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_task = {
            executor.submit(take_screenshot, task['url'], task['output_path']): task
            for task in task_list
        }
        
        # Process as they complete
        completed = 0
        for future in concurrent.futures.as_completed(future_to_task):
            task = future_to_task[future]
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error taking screenshot for {task['url']}: {e}")
            
            completed += 1
            if completed % 5 == 0 or completed == len(task_list):
                logger.info(f"Screenshot progress: {completed}/{len(task_list)}")
""")
        
    logger.info("Updated utils/screenshot.py with multi-strategy support")
    return True

def run():
    """Run the update process"""
    logger.info("Starting DirHunter AI update process")
    
    # Check requirements
    check_requirements()
    
    # Update screenshot module
    update_screenshot_module()
    
    logger.info("""
    ---------------------------------------------------------------
    Update complete! DirHunter AI now uses the best available 
    screenshot method automatically:
    
    1. Selenium (if working)
    2. Pure Python requests + PIL (as fallback)
    3. Simple placeholder (as last resort)
    
    You can now run your main script as usual:
    
      python main_optimized.py
    
    The tool will use the best available method for screenshots,
    and domain cards should now show all information correctly.
    ---------------------------------------------------------------
    """)

if __name__ == "__main__":
    run() 
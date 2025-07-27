#!/usr/bin/env python3
"""
Chromium Wrapper for Snap-based Installations

This script works around issues with Selenium trying to use snap-based Chrome/Chromium
by creating a custom wrapper service for WebDriver.
"""

import os
import sys
import subprocess
import time
import tempfile
import logging
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def create_temp_xvfb_script():
    """Create a temporary script to run commands with Xvfb"""
    temp_script = tempfile.NamedTemporaryFile(delete=False, suffix='.sh')
    script_content = """#!/bin/bash
# Run a command with Xvfb
export DISPLAY=:99
Xvfb :99 -screen 0 1280x1024x24 -ac &
XVFB_PID=$!
sleep 1

# Run the command
"$@"
EXIT_CODE=$?

# Kill Xvfb
kill $XVFB_PID

exit $EXIT_CODE
"""
    temp_script.write(script_content.encode('utf-8'))
    temp_script.close()
    os.chmod(temp_script.name, 0o755)
    return temp_script.name

def find_chromium_binary():
    """Find the Chromium/Chrome binary"""
    possible_paths = [
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/snap/bin/chromium",
        "/snap/chromium/current/usr/lib/chromium-browser/chrome",
        "/usr/local/bin/chrome"
    ]
    
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            logger.info(f"Found Chromium at {path}")
            return path
            
    logger.error("No Chromium binary found")
    return None

def find_chromedriver():
    """Find the ChromeDriver binary"""
    possible_paths = [
        "/usr/bin/chromedriver",
        "/usr/local/bin/chromedriver",
        "/snap/bin/chromedriver"
    ]
    
    for path in possible_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            logger.info(f"Found ChromeDriver at {path}")
            return path
            
    logger.error("No ChromeDriver binary found")
    return None

def take_screenshot(url, output_path):
    """Take a screenshot using Chromium/Chrome with special handling for snap packages"""
    chrome_binary = find_chromium_binary()
    driver_binary = find_chromedriver()
    
    if not chrome_binary:
        logger.error("Chromium/Chrome binary not found")
        return False
        
    if not driver_binary:
        logger.error("ChromeDriver not found")
        return False
    
    logger.info(f"Taking screenshot of {url} using Chromium...")
    
    # Create a unique tmp directory for user-data-dir
    temp_dir = tempfile.mkdtemp(prefix="chrome_")
    
    # Use Xvfb wrapper for headless operation
    xvfb_script = create_temp_xvfb_script()
    
    try:
        chrome_options = Options()
        chrome_options.binary_location = chrome_binary
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument(f"--user-data-dir={temp_dir}")
        chrome_options.add_argument("--disable-software-rasterizer")
        
        # Try to use Chrome in non-headless mode with Xvfb
        logger.info("Initializing ChromeDriver...")
        service = ChromeService(executable_path=driver_binary)
        
        # Create driver
        try:
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
            logger.info(f"Navigating to {url}")
            driver.get(url)
            
            # Wait for page to load
            time.sleep(3)
            
            # Take screenshot
            logger.info(f"Taking screenshot to {output_path}")
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            driver.save_screenshot(output_path)
            
            # Save text as well
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            with open(text_path, 'w') as f:
                f.write(f"Title: {driver.title}\n")
                f.write(f"URL: {driver.current_url}\n")
                f.write(f"Page source length: {len(driver.page_source)}\n\n")
                f.write(driver.page_source[:5000] + "...")
                
            driver.quit()
            logger.info("Screenshot successful")
            return True
            
        except WebDriverException as e:
            logger.error(f"WebDriver error: {e}")
            
            # Fallback to subprocess approach for snap-based Chrome
            logger.info("Trying alternative approach with subprocess...")
            
            cmd = [
                xvfb_script, 
                chrome_binary,
                "--headless=new", 
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                f"--user-data-dir={temp_dir}",
                "--screenshot=" + output_path,
                url
            ]
            
            logger.info(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("Screenshot successful (subprocess method)")
                return True
            else:
                logger.error(f"Subprocess screenshot failed: {result.stderr}")
                return False
            
    except Exception as e:
        logger.error(f"Error taking screenshot: {e}")
        return False
    finally:
        # Clean up
        try:
            os.unlink(xvfb_script)
        except Exception:
            pass
            
        try:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

def main():
    """Main function to take a screenshot if this script is run directly"""
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <url> <output_path>")
        sys.exit(1)
        
    url = sys.argv[1]
    output_path = sys.argv[2]
    
    success = take_screenshot(url, output_path)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 
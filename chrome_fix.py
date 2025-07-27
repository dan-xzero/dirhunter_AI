#!/usr/bin/env python3
"""
Chrome Fix - Advanced troubleshooting for Chrome/Selenium issues
"""

import os
import sys
import time
import logging
import tempfile
import shutil
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def find_chrome_binary():
    """Find Chrome or Chromium binary on the system"""
    possible_paths = [
        # Linux paths
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
        # macOS
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        # Windows
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            logger.info(f"Found Chrome at: {path}")
            return path
            
    logger.warning("Could not find Chrome binary in common locations")
    return None

def install_chrome_if_needed():
    """Try to install Chrome if not found"""
    if sys.platform.startswith('linux'):
        logger.info("Attempting to install Chrome on Linux...")
        try:
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "chromium-browser"], check=True)
            if os.path.exists("/usr/bin/chromium-browser"):
                logger.info("Successfully installed Chromium")
                return "/usr/bin/chromium-browser"
        except Exception as e:
            logger.error(f"Failed to install Chrome: {e}")
    return None

def try_webdriver_manager():
    """Try using webdriver-manager to handle Chrome driver installation"""
    logger.info("Attempting to use webdriver-manager...")
    
    try:
        # Try to import webdriver_manager
        try:
            from webdriver_manager.chrome import ChromeDriverManager
            from selenium import webdriver
            from selenium.webdriver.chrome.service import Service
            
            logger.info("webdriver_manager is installed, trying to set up Chrome")
            
            # Use ChromeDriverManager to handle driver installation
            service = Service(ChromeDriverManager().install())
            
            # Setup Chrome with very minimal options
            options = webdriver.ChromeOptions()
            options.add_argument("--headless=new")  # Use new headless mode
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option("useAutomationExtension", False)
            
            # Try to start Chrome
            logger.info("Starting Chrome with webdriver-manager...")
            driver = webdriver.Chrome(service=service, options=options)
            
            # Take a test screenshot
            output_path = os.path.join(tempfile.gettempdir(), "test_screenshot.png")
            driver.get("https://www.example.com")
            driver.save_screenshot(output_path)
            logger.info(f"Success! Screenshot saved to {output_path}")
            
            driver.quit()
            return True
        except ImportError:
            logger.warning("webdriver_manager not installed, trying to install it...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "webdriver-manager"])
                logger.info("Successfully installed webdriver-manager, please run this script again")
            except Exception as e:
                logger.error(f"Failed to install webdriver-manager: {e}")
            return False
    except Exception as e:
        logger.error(f"Failed to use webdriver-manager: {e}")
        return False

def try_direct_chrome_binary():
    """Try using Chrome binary directly with various options"""
    logger.info("Attempting direct Chrome binary approach...")
    
    chrome_binary = find_chrome_binary()
    if not chrome_binary:
        chrome_binary = install_chrome_if_needed()
    
    if not chrome_binary:
        logger.error("Could not find or install Chrome")
        return False
    
    # Test configurations to try
    configs = [
        {
            "name": "Minimal",
            "options": ["--headless=new", "--disable-gpu", "--no-sandbox"]
        },
        {
            "name": "With Remote Debugging",
            "options": ["--headless=new", "--no-sandbox", "--remote-debugging-port=9222"]
        },
        {
            "name": "With Temp Data Dir",
            "options": ["--headless=new", "--no-sandbox", f"--user-data-dir={tempfile.mkdtemp()}"]
        }
    ]
    
    for config in configs:
        logger.info(f"Trying {config['name']} configuration...")
        
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.service import Service
            from selenium.webdriver.chrome.options import Options
            
            options = Options()
            for opt in config["options"]:
                options.add_argument(opt)
                
            # Set binary location explicitly
            options.binary_location = chrome_binary
            
            # Create a new temp directory for each attempt
            tmp_dir = tempfile.mkdtemp()
            
            try:
                # Create Service with log path for debugging
                log_path = os.path.join(tmp_dir, "chromedriver.log")
                service = Service(log_path=log_path)
                
                # Try to start Chrome
                driver = webdriver.Chrome(service=service, options=options)
                
                # Take a test screenshot
                output_path = os.path.join(tmp_dir, "test_screenshot.png")
                driver.get("https://www.example.com")
                driver.save_screenshot(output_path)
                logger.info(f"Success! Screenshot saved to {output_path}")
                
                driver.quit()
                return True
            except Exception as e:
                logger.error(f"Configuration failed: {e}")
                
                # Check for error logs
                if os.path.exists(log_path):
                    with open(log_path, 'r') as f:
                        log_content = f.read()
                    logger.debug(f"ChromeDriver logs: {log_content[:500]}...")
                    
                # Clean up
                shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception as e:
            logger.error(f"Failed to set up Chrome: {e}")
    
    return False

def fix_chrome_issues():
    """Try multiple approaches to fix Chrome issues"""
    logger.info("Starting Chrome troubleshooting...")
    
    # First try webdriver-manager approach
    if try_webdriver_manager():
        logger.info("Successfully fixed Chrome issues using webdriver-manager!")
        return True
    
    # If that fails, try direct binary approach
    if try_direct_chrome_binary():
        logger.info("Successfully fixed Chrome issues using direct binary approach!")
        return True
    
    logger.error("All Chrome fixing attempts failed")
    logger.info("Recommendation: Use the fallback screenshot mechanism")
    return False

if __name__ == "__main__":
    fix_chrome_issues() 
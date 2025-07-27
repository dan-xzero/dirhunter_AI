#!/usr/bin/env python3
"""
Test Screenshot Functionality (Fixed)

This script tests if screenshots can be captured on the local machine,
using both Selenium and our fallback mechanism.
"""

import os
import sys
import time
import logging
import tempfile
import shutil
import uuid

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def test_selenium_screenshot(url, output_path):
    """Test if Selenium can take a screenshot"""
    logger.info(f"Testing Selenium screenshot of {url}")
    
    # Create a unique temporary directory for Chrome user data
    temp_dir = os.path.join(tempfile.gettempdir(), f"chrome_temp_{uuid.uuid4().hex}")
    os.makedirs(temp_dir, exist_ok=True)
    
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        
        # Setup Chrome options
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument(f"--user-data-dir={temp_dir}")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-plugins")
        
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        logger.info("Initializing Chrome webdriver...")
        
        try:
            # Try with Service object first
            service = Service()
            driver = webdriver.Chrome(service=service, options=chrome_options)
        except Exception as e:
            logger.warning(f"Could not initialize with Service: {e}")
            # Fall back to direct initialization
            driver = webdriver.Chrome(options=chrome_options)
        
        try:
            driver.set_page_load_timeout(30)
            logger.info(f"Navigating to {url}...")
            driver.get(url)
            
            logger.info("Taking screenshot...")
            driver.save_screenshot(output_path)
            
            logger.info(f"Screenshot saved to {output_path}")
            return True
        finally:
            driver.quit()
            
    except Exception as e:
        logger.error(f"Selenium screenshot failed: {e}")
        return False
    finally:
        # Clean up the temporary directory
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.info(f"Cleaned up temporary Chrome directory: {temp_dir}")
        except Exception as e:
            logger.error(f"Error cleaning up temporary directory: {e}")

def test_fallback_screenshot(url, output_path):
    """Test if our fallback can create a placeholder screenshot"""
    logger.info("Testing fallback screenshot mechanism")
    
    try:
        from utils.screenshot_fallback import create_placeholder_screenshot
        
        result = create_placeholder_screenshot(url, output_path)
        if result:
            logger.info(f"Fallback screenshot saved to {output_path}")
        else:
            logger.error("Fallback screenshot failed")
        return result
    except ImportError:
        logger.error("Fallback screenshot module not available")
        return False
    except Exception as e:
        logger.error(f"Fallback screenshot error: {e}")
        return False

def main():
    # Test URL
    url = "https://www.example.com"
    
    # Output paths
    output_dir = "test_screenshots"
    os.makedirs(output_dir, exist_ok=True)
    
    selenium_output = os.path.join(output_dir, "selenium_screenshot.png")
    fallback_output = os.path.join(output_dir, "fallback_screenshot.png")
    
    # Test Selenium screenshot
    logger.info("=== Testing Selenium Screenshot ===")
    selenium_success = test_selenium_screenshot(url, selenium_output)
    
    # Test fallback screenshot
    logger.info("=== Testing Fallback Screenshot ===")
    fallback_success = test_fallback_screenshot(url, fallback_output)
    
    # Summary
    logger.info("=== Summary ===")
    logger.info(f"Selenium screenshot: {'SUCCESS' if selenium_success else 'FAILED'}")
    logger.info(f"Fallback screenshot: {'SUCCESS' if fallback_success else 'FAILED'}")
    
    if selenium_success:
        logger.info(f"Selenium screenshot saved to: {selenium_output}")
    if fallback_success:
        logger.info(f"Fallback screenshot saved to: {fallback_output}")
    
    if not selenium_success and not fallback_success:
        logger.error("Both screenshot methods failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 
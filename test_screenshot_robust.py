#!/usr/bin/env python3
"""
Test Screenshot Functionality (Robust)

This script tests if screenshots can be captured on the local machine,
using multiple Chrome configurations and providing detailed diagnostics.
"""

import os
import sys
import time
import logging
import platform
import subprocess
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

def show_system_info():
    """Display relevant system information for debugging"""
    logger.info("=== System Information ===")
    logger.info(f"Platform: {platform.platform()}")
    logger.info(f"Python: {platform.python_version()}")
    
    # Check Chrome/Chromium
    chrome_paths = [
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
    ]
    
    chrome_found = False
    for path in chrome_paths:
        if os.path.exists(path):
            try:
                # Get Chrome version
                result = subprocess.run([path, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
                logger.info(f"Chrome found: {path} - {result.stdout.strip()}")
                chrome_found = True
                break
            except Exception:
                pass
    
    if not chrome_found:
        logger.warning("Chrome/Chromium not found in common locations")
    
    # Check selenium
    try:
        import selenium
        logger.info(f"Selenium version: {selenium.__version__}")
    except ImportError:
        logger.error("Selenium not installed")

def test_selenium_configurations(url, output_base):
    """Test multiple Chrome configurations"""
    logger.info("=== Testing Multiple Chrome Configurations ===")
    
    configs = [
        {
            "name": "Standard",
            "options": [
                "--headless", 
                "--no-sandbox", 
                "--disable-dev-shm-usage"
            ]
        },
        {
            "name": "No User Data",
            "options": [
                "--headless", 
                "--no-sandbox", 
                "--disable-dev-shm-usage",
                "--disable-gpu"
            ]
        },
        {
            "name": "Incognito",
            "options": [
                "--headless", 
                "--no-sandbox", 
                "--disable-dev-shm-usage",
                "--incognito"
            ]
        }
    ]
    
    for i, config in enumerate(configs, 1):
        output_path = f"{output_base}_config{i}.png"
        logger.info(f"Testing config {i}: {config['name']}")
        
        # Create unique temp directory for this config
        temp_dir = os.path.join(tempfile.gettempdir(), f"chrome_temp_{uuid.uuid4().hex}")
        os.makedirs(temp_dir, exist_ok=True)
        
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            chrome_options = Options()
            for option in config["options"]:
                chrome_options.add_argument(option)
                
            # Add unique user data dir to prevent conflicts
            chrome_options.add_argument(f"--user-data-dir={temp_dir}")
            
            try:
                driver = webdriver.Chrome(options=chrome_options)
                
                try:
                    logger.info(f"Navigating to {url}")
                    driver.get(url)
                    
                    # Take screenshot
                    driver.save_screenshot(output_path)
                    logger.info(f"SUCCESS! Screenshot saved to {output_path}")
                    return True
                finally:
                    driver.quit()
            except Exception as e:
                logger.error(f"Config {i} failed: {e}")
        except Exception as e:
            logger.error(f"Failed to initialize Chrome with config {i}: {e}")
        finally:
            # Clean up
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
                
    return False

def test_fallback_screenshot(url, output_path):
    """Test if our fallback can create a placeholder screenshot"""
    logger.info("=== Testing Fallback Screenshot ===")
    
    try:
        # First try to import from utils
        try:
            from utils.screenshot_fallback import create_placeholder_screenshot
            result = create_placeholder_screenshot(url, output_path)
            if result:
                logger.info(f"Fallback screenshot saved to {output_path}")
                return True
            else:
                logger.error("Fallback screenshot function returned False")
                return False
        except ImportError:
            # Inline implementation as fallback
            logger.warning("Fallback module not found, trying inline implementation")
            
            try:
                from PIL import Image, ImageDraw
                
                # Create a simple placeholder image
                width, height = 1280, 800
                img = Image.new('RGB', (width, height), color=(240, 240, 240))
                draw = ImageDraw.Draw(img)
                
                # Add text to the image
                lines = [
                    "Screenshot Not Available",
                    f"URL: {url}",
                    "Generated by inline fallback"
                ]
                
                # Add text centered on the image
                y_position = height // 4
                for line in lines:
                    # Simple center alignment
                    text_width = len(line) * 10  # Rough estimate
                    x_position = (width - text_width) // 2
                    draw.text((x_position, y_position), line, fill=(70, 70, 70))
                    y_position += 40
                    
                # Create output directory if needed
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                # Save the image
                img.save(output_path)
                logger.info(f"Inline fallback screenshot saved to {output_path}")
                return True
            except Exception as e:
                logger.error(f"Inline fallback failed: {e}")
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
    
    selenium_output_base = os.path.join(output_dir, "selenium_screenshot")
    fallback_output = os.path.join(output_dir, "fallback_screenshot.png")
    
    # Show system info
    show_system_info()
    
    # Test Selenium with multiple configurations
    selenium_success = test_selenium_configurations(url, selenium_output_base)
    
    # Test fallback
    fallback_success = test_fallback_screenshot(url, fallback_output)
    
    # Summary
    logger.info("=== Summary ===")
    logger.info(f"Selenium screenshot: {'SUCCESS' if selenium_success else 'FAILED'}")
    logger.info(f"Fallback screenshot: {'SUCCESS' if fallback_success else 'FAILED'}")
    
    if not selenium_success:
        logger.info("Chrome appears to be having issues on this system")
        logger.info("The tool will use fallback placeholder screenshots")
    
    if not selenium_success and not fallback_success:
        logger.error("Both screenshot methods failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 
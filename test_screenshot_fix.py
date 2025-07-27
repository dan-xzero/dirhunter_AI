#!/usr/bin/env python3
"""
Test script to verify screenshot functionality
"""

import os
import sys
import logging
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Import the screenshot functions
from utils.screenshot import (
    initialize_screenshot_system,
    take_screenshot,
    clean_browser_environment
)

def main():
    # Create output directory
    output_dir = "test_screenshots"
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize screenshot system
    logging.info("Initializing screenshot system...")
    initialize_screenshot_system(max_workers=1)
    
    # Clean any existing browser processes
    logging.info("Cleaning browser environment...")
    clean_browser_environment()
    
    # List of test URLs
    test_urls = [
        "https://www.example.com",
        "https://www.google.com",
        "https://www.github.com"
    ]
    
    # Take screenshots for each URL
    for i, url in enumerate(test_urls):
        logging.info(f"Taking screenshot for {url} ({i+1}/{len(test_urls)})")
        
        # Create output path
        output_path = os.path.join(output_dir, f"screenshot_{i+1}.png")
        
        # Take screenshot
        start_time = time.time()
        success = take_screenshot(url, output_path)
        end_time = time.time()
        
        # Check result
        if success:
            logging.info(f"✓ Screenshot saved to {output_path} ({end_time - start_time:.2f}s)")
            
            # Check if text file also exists
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            if os.path.exists(text_path):
                with open(text_path, 'r') as f:
                    text_content = f.read()
                logging.info(f"Text content snippet: {text_content[:100]}...")
        else:
            logging.error(f"✗ Failed to take screenshot for {url}")
        
        # Small delay between screenshots
        time.sleep(1)
    
    # Final cleanup
    logging.info("Final browser cleanup...")
    clean_browser_environment()
    
    # Show output files
    logging.info(f"Files in {output_dir}:")
    for file in sorted(os.listdir(output_dir)):
        file_path = os.path.join(output_dir, file)
        file_size = os.path.getsize(file_path) / 1024  # KB
        logging.info(f"  {file} ({file_size:.1f} KB)")

if __name__ == "__main__":
    main() 
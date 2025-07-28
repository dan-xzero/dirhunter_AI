#!/usr/bin/env python3
"""
Test Script for Screenshot Functionality

This script tests the screenshot functionality to verify it works correctly.
It will attempt to take screenshots of several test URLs using the direct
method, browser method, and fallback method.
"""

import os
import sys
import logging
import time
import shutil
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger()

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import screenshot functionality
from utils.screenshot import (
    initialize_screenshot_system,
    clean_browser_environment,
    take_screenshot,
    take_direct_screenshot,
    take_browser_screenshot,
    create_fallback_screenshot
)

def print_separator(title=None):
    """Print a separator line with optional title"""
    width = 80
    if title:
        padding = (width - len(title) - 4) // 2
        print("=" * padding + f" {title} " + "=" * padding)
    else:
        print("=" * width)

def test_screenshot(url, method="all"):
    """Test taking a screenshot of a URL"""
    # Create output directory
    output_dir = "test_screenshots"
    os.makedirs(output_dir, exist_ok=True)
    
    # Create a timestamped filename to avoid overwriting
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    method_str = method if method != "all" else "combined"
    filename = f"{url.replace('://', '_').replace('/', '_').replace('.', '_')}_{method_str}_{timestamp}.png"
    output_path = os.path.join(output_dir, filename)
    
    print_separator(f"Testing {method} screenshot for {url}")
    print(f"Output file: {output_path}")
    
    start_time = time.time()
    success = False
    
    try:
        if method == "direct":
            success = take_direct_screenshot(url, output_path)
        elif method == "browser":
            success = take_browser_screenshot(url, output_path)
        elif method == "fallback":
            success = create_fallback_screenshot(url, output_path)
        else:  # "all" - use the main function that tries all methods
            success = take_screenshot(url, output_path)
        
        duration = time.time() - start_time
        
        if success:
            print(f"✅ Screenshot succeeded ({duration:.2f}s)")
            # Check if image and text files exist
            if os.path.exists(output_path):
                image_size = os.path.getsize(output_path) / 1024  # KB
                print(f"   Image file size: {image_size:.2f} KB")
            
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            if os.path.exists(text_path):
                text_size = os.path.getsize(text_path) / 1024  # KB
                print(f"   Text file size: {text_size:.2f} KB")
                
                # Show snippet of text content
                try:
                    with open(text_path, 'r', encoding='utf-8') as f:
                        content = f.read(200)
                    print(f"   Text snippet: {content[:100]}...")
                except Exception as e:
                    print(f"   Could not read text content: {e}")
        else:
            print(f"❌ Screenshot failed ({duration:.2f}s)")
        
        return success
    except Exception as e:
        duration = time.time() - start_time
        print(f"❌ Exception occurred: {e} ({duration:.2f}s)")
        return False

def run_tests():
    """Run all screenshot tests"""
    print_separator("SCREENSHOT TEST SUITE")
    print(f"Starting tests at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Initialize screenshot system
    initialize_screenshot_system()
    
    # Clean environment before testing
    clean_browser_environment()
    
    # List of test URLs
    test_urls = [
        "https://www.example.com",
        "https://www.google.com",
        "https://www.github.com"
    ]
    
    # Test all methods for each URL
    overall_success = True
    
    # First test the combined (automatic fallback) approach
    print_separator("TESTING COMBINED APPROACH (ALL METHODS)")
    for url in test_urls:
        if not test_screenshot(url, "all"):
            overall_success = False
    
    # Then test each method individually
    for method in ["direct", "browser", "fallback"]:
        print_separator(f"TESTING {method.upper()} METHOD")
        
        for url in test_urls:
            if not test_screenshot(url, method):
                overall_success = False
    
    # Clean up after tests
    print_separator("CLEANING UP")
    clean_browser_environment()
    
    # Report results
    print_separator("TEST RESULTS")
    if overall_success:
        print("✅ All tests completed successfully")
    else:
        print("❌ Some tests failed")
    
    # List files in test directory
    test_dir = "test_screenshots"
    if os.path.exists(test_dir) and os.path.isdir(test_dir):
        files = os.listdir(test_dir)
        print(f"\nFiles in {test_dir}:")
        for f in files:
            size = os.path.getsize(os.path.join(test_dir, f)) / 1024  # KB
            print(f"   {f} ({size:.1f} KB)")
    
    return overall_success

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1) 
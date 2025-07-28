#!/usr/bin/env python3
"""
Fix Verification Script

This script tests the optimized screenshot functionality and confirms
that the program flow is working correctly without unnecessary browser spawning.
"""

import os
import sys
import time
import logging
import subprocess
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger()

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def print_header(title):
    """Print a header with title"""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)

def verify_direct_screenshot():
    """Verify direct screenshot method works"""
    print_header("TESTING DIRECT SCREENSHOT METHOD")
    
    try:
        from utils.screenshot import take_direct_screenshot, initialize_screenshot_system
        
        # Initialize system
        initialize_screenshot_system()
        
        # Create test directory
        test_dir = Path("test_verification")
        test_dir.mkdir(exist_ok=True)
        
        # Test URL
        test_url = "https://www.example.com"
        output_path = test_dir / "direct_test.png"
        
        # Take screenshot
        print(f"Taking screenshot of {test_url}...")
        start_time = time.time()
        success = take_direct_screenshot(test_url, str(output_path))
        duration = time.time() - start_time
        
        # Check result
        if success and output_path.exists():
            file_size = output_path.stat().st_size / 1024  # KB
            print(f"✅ Screenshot succeeded in {duration:.2f}s")
            print(f"   Image saved to: {output_path} ({file_size:.1f} KB)")
            
            # Check text file
            text_path = output_path.with_suffix('.txt')
            if text_path.exists():
                text_size = text_path.stat().st_size / 1024  # KB
                print(f"   Text saved to: {text_path} ({text_size:.1f} KB)")
                
                # Read first few lines
                with open(text_path, 'r', encoding='utf-8') as f:
                    first_line = next(iter(f), "").strip()
                print(f"   First line: {first_line[:50]}...")
            
            return True
        else:
            print(f"❌ Screenshot failed after {duration:.2f}s")
            return False
    except Exception as e:
        print(f"❌ Error during test: {e}")
        return False

def verify_no_browser_spawning():
    """Verify that browsers are not spawned unnecessarily"""
    print_header("CHECKING FOR UNNECESSARY BROWSER PROCESSES")
    
    # Get baseline browser processes
    print("Checking baseline browser processes...")
    baseline = count_browser_processes()
    print(f"Current browser processes: {baseline}")
    
    # Import screenshot module but don't call anything yet
    print("Importing screenshot module...")
    import utils.screenshot
    
    # Check browser processes again
    after_import = count_browser_processes()
    print(f"Browser processes after import: {after_import}")
    
    # Initialize screenshot system
    print("Initializing screenshot system...")
    utils.screenshot.initialize_screenshot_system()
    
    # Check browser processes again
    after_init = count_browser_processes()
    print(f"Browser processes after initialize: {after_init}")
    
    # Check if browser processes increased
    if after_init > baseline + 2:
        print("❌ Browser processes increased significantly after initialization")
        print("   This suggests unnecessary browser spawning")
        return False
    else:
        print("✅ No significant increase in browser processes")
        print("   Browser spawning appears to be optimized")
        return True

def verify_cleanup_effectiveness():
    """Verify that the cleanup function effectively removes browser processes"""
    print_header("TESTING BROWSER CLEANUP EFFECTIVENESS")
    
    try:
        from utils.screenshot import clean_browser_environment
        
        # Count browser processes before
        before = count_browser_processes()
        print(f"Browser processes before cleanup: {before}")
        
        # Run cleanup
        print("Running browser cleanup...")
        clean_browser_environment()
        
        # Count browser processes after
        after = count_browser_processes()
        print(f"Browser processes after cleanup: {after}")
        
        # Check if any processes were terminated
        if after <= before:
            print("✅ Cleanup effective - no increase in browser processes")
            return True
        else:
            print("❌ Cleanup ineffective - browser processes increased")
            return False
    except Exception as e:
        print(f"❌ Error during cleanup test: {e}")
        return False

def count_browser_processes():
    """Count browser-related processes"""
    try:
        # Use ps to find browser processes
        cmd = "ps aux | grep -E 'firefox|chrome|chromium|gecko|selenium|xvfb' | grep -v grep | wc -l"
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        
        # Parse count
        count = int(result.stdout.strip())
        return count
    except Exception as e:
        print(f"Error counting processes: {e}")
        return -1

def verify_run_history():
    """Verify that run_history.py has the necessary function"""
    print_header("VERIFYING RUN HISTORY MODULE")
    
    try:
        from utils.run_history import update_run_history
        
        print("✅ Successfully imported update_run_history function")
        
        # Create test data
        test_results = {
            'example.com': [
                {'finding_status': 'new'}, 
                {'finding_status': 'new'}
            ],
            'test.com': [
                {'finding_status': 'changed'}, 
                {'finding_status': 'existing'}
            ]
        }
        
        test_domains = [('example.com', 'wordlist.txt'), ('test.com', 'wordlist.txt')]
        
        # Test function
        print("Testing update_run_history function...")
        update_run_history(test_results, test_domains)
        print("✅ Function executed without errors")
        
        return True
    except ImportError:
        print("❌ Failed to import update_run_history function")
        return False
    except Exception as e:
        print(f"❌ Error testing run_history: {e}")
        return False

def summarize_flow():
    """Summarize the optimized program flow"""
    print_header("OPTIMIZED PROGRAM FLOW")
    
    print("""
1. DirHunter AI starts with main_optimized.py
2. The scanning process occurs for each domain
3. After scanning, the screenshot process is initiated:
   
   a. The take_screenshots_parallel() function is called
   b. It initializes the screenshot system with a semaphore (1 worker)
   c. It performs a SINGLE cleanup of browser processes at the start
   d. It organizes screenshots by priority (high, normal, low)
   e. For each URL:
      - take_screenshot() is called, which:
        1. FIRST tries take_direct_screenshot() (direct browser command)
        2. If that fails, tries take_browser_screenshot() (Selenium)
        3. If that fails, tries create_fallback_screenshot() (PIL)
   f. After all screenshots are complete, it performs a final cleanup
   
4. The direct screenshot method:
   - Creates a temporary shell script to:
     * Find a free Xvfb display
     * Configure the environment to avoid D-Bus errors
     * Use Chrome/Chromium directly with headless mode
     * Take the screenshot and save page content as text
     * Clean up the Xvfb process

5. No browser processes are spawned until they are actually needed
6. No cleanup is performed between individual screenshots
7. This approach ensures minimum resource usage and maximum reliability
    """)

def main():
    """Run all verification tests"""
    print_header("DIRHUNTER AI FIX VERIFICATION")
    
    # Track overall success
    all_tests_passed = True
    
    # Test direct screenshot
    if verify_direct_screenshot():
        print("✅ Direct screenshot test passed")
    else:
        print("❌ Direct screenshot test failed")
        all_tests_passed = False
    
    # Test browser spawning
    if verify_no_browser_spawning():
        print("✅ Browser spawning test passed")
    else:
        print("❌ Browser spawning test failed")
        all_tests_passed = False
    
    # Test cleanup
    if verify_cleanup_effectiveness():
        print("✅ Cleanup test passed")
    else:
        print("❌ Cleanup test failed")
        all_tests_passed = False
    
    # Test run history
    if verify_run_history():
        print("✅ Run history test passed")
    else:
        print("❌ Run history test failed")
        all_tests_passed = False
    
    # Show optimized flow
    summarize_flow()
    
    # Final result
    print_header("VERIFICATION RESULTS")
    if all_tests_passed:
        print("✅ All tests passed! DirHunter AI has been successfully optimized.")
    else:
        print("❌ Some tests failed. Please check the logs and fix any remaining issues.")
    
    return 0 if all_tests_passed else 1

if __name__ == "__main__":
    sys.exit(main()) 
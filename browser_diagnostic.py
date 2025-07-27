#!/usr/bin/env python3
"""
Browser Diagnostic and Fix Tool

This script diagnoses and attempts to fix issues with running browsers
in headless environments like SSH servers. It focuses on Chrome/Chromium
and Firefox setups for Selenium.
"""

import os
import sys
import subprocess
import shutil
import platform
import stat
import logging
import time
import tempfile
import json
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ===== BROWSER PATHS =====

CHROME_PATHS = [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
    "/snap/chromium/current/usr/lib/chromium-browser/chrome"
]

FIREFOX_PATHS = [
    "/usr/bin/firefox",
    "/snap/bin/firefox",
    "/snap/firefox/current/firefox",
    "/usr/lib/firefox/firefox"
]

CHROMEDRIVER_PATHS = [
    "/usr/bin/chromedriver",
    "/usr/local/bin/chromedriver",
    "/snap/bin/chromedriver"
]

GECKODRIVER_PATHS = [
    "/usr/bin/geckodriver",
    "/usr/local/bin/geckodriver",
    "/snap/bin/geckodriver"
]

# ===== HELPER FUNCTIONS =====

def run_command(command, timeout=10, check=False):
    """Run a command and return its output"""
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=check
        )
        return {
            'returncode': process.returncode,
            'stdout': process.stdout,
            'stderr': process.stderr,
            'success': process.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            'returncode': -1,
            'stdout': '',
            'stderr': 'Command timed out',
            'success': False,
            'timeout': True
        }
    except Exception as e:
        return {
            'returncode': -2,
            'stdout': '',
            'stderr': str(e),
            'success': False
        }

def check_executable(path):
    """Check if a file exists and is executable"""
    if not os.path.exists(path):
        return False
    if not os.path.isfile(path):
        return False
    return os.access(path, os.X_OK)

def get_package_manager():
    """Determine the system package manager"""
    package_managers = {
        'apt': '/usr/bin/apt',
        'apt-get': '/usr/bin/apt-get',
        'yum': '/usr/bin/yum',
        'dnf': '/usr/bin/dnf',
        'zypper': '/usr/bin/zypper',
        'pacman': '/usr/bin/pacman'
    }
    
    for name, path in package_managers.items():
        if os.path.exists(path):
            return name
            
    return None

def create_symlink(source, target):
    """Create a symlink from source to target"""
    try:
        if os.path.exists(target):
            os.remove(target)
        os.symlink(source, target)
        return True
    except Exception as e:
        logger.error(f"Failed to create symlink: {e}")
        return False

# ===== BROWSER CHECKS =====

def find_browser(browser_type):
    """Find a browser binary"""
    if browser_type == 'chrome':
        paths = CHROME_PATHS
    else:  # firefox
        paths = FIREFOX_PATHS
    
    for path in paths:
        if check_executable(path):
            logger.info(f"Found {browser_type} at {path}")
            # Test if it's actually runnable
            result = run_command([path, '--version'])
            if result['success']:
                logger.info(f"{browser_type.title()} version: {result['stdout'].strip()}")
                return path
            else:
                logger.warning(f"{path} exists but failed to run: {result['stderr']}")
    
    logger.error(f"No working {browser_type} found")
    return None

def find_driver(driver_type):
    """Find a webdriver binary"""
    if driver_type == 'chromedriver':
        paths = CHROMEDRIVER_PATHS
    else:  # geckodriver
        paths = GECKODRIVER_PATHS
    
    for path in paths:
        if check_executable(path):
            logger.info(f"Found {driver_type} at {path}")
            # Test if it's actually runnable
            result = run_command([path, '--version'])
            if result['success']:
                logger.info(f"{driver_type} version: {result['stdout'].strip()}")
                return path
            else:
                logger.warning(f"{path} exists but failed to run: {result['stderr']}")
    
    logger.error(f"No working {driver_type} found")
    return None

# ===== BROWSER TESTS =====

def test_chrome_with_driver():
    """Test Chrome with ChromeDriver"""
    chrome_path = find_browser('chrome')
    driver_path = find_driver('chromedriver')
    
    if not chrome_path or not driver_path:
        logger.error("Cannot test Chrome with driver: binary or driver missing")
        return False
    
    logger.info(f"Testing Chrome with ChromeDriver...")
    
    # Try to run a simple test with selenium
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.service import Service as ChromeService
        from selenium.webdriver.chrome.options import Options as ChromeOptions
        
        options = ChromeOptions()
        options.binary_location = chrome_path
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        
        temp_dir = tempfile.mkdtemp()
        options.add_argument(f"--user-data-dir={temp_dir}")
        
        service = ChromeService(executable_path=driver_path)
        
        logger.info("Launching Chrome...")
        driver = webdriver.Chrome(service=service, options=options)
        
        logger.info("Opening example.com...")
        driver.get("https://www.example.com")
        
        title = driver.title
        logger.info(f"Page title: {title}")
        
        # Take screenshot
        screenshot_path = os.path.join(os.getcwd(), "chrome_test.png")
        driver.save_screenshot(screenshot_path)
        logger.info(f"Screenshot saved to {screenshot_path}")
        
        driver.quit()
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        logger.info("Chrome with ChromeDriver test: SUCCESS ✅")
        return True
        
    except Exception as e:
        logger.error(f"Chrome with ChromeDriver test failed: {e}")
        logger.info("Chrome with ChromeDriver test: FAILED ❌")
        return False

def test_firefox_with_driver():
    """Test Firefox with GeckoDriver"""
    firefox_path = find_browser('firefox')
    driver_path = find_driver('geckodriver')
    
    if not firefox_path or not driver_path:
        logger.error("Cannot test Firefox with driver: binary or driver missing")
        return False
    
    logger.info(f"Testing Firefox with GeckoDriver...")
    
    # Try to run a simple test with selenium
    try:
        from selenium import webdriver
        from selenium.webdriver.firefox.service import Service as FirefoxService
        from selenium.webdriver.firefox.options import Options as FirefoxOptions
        
        options = FirefoxOptions()
        options.binary_location = firefox_path
        options.add_argument("--headless")
        
        service = FirefoxService(executable_path=driver_path)
        
        logger.info("Launching Firefox...")
        driver = webdriver.Firefox(service=service, options=options)
        
        logger.info("Opening example.com...")
        driver.get("https://www.example.com")
        
        title = driver.title
        logger.info(f"Page title: {title}")
        
        # Take screenshot
        screenshot_path = os.path.join(os.getcwd(), "firefox_test.png")
        driver.save_screenshot(screenshot_path)
        logger.info(f"Screenshot saved to {screenshot_path}")
        
        driver.quit()
        
        logger.info("Firefox with GeckoDriver test: SUCCESS ✅")
        return True
        
    except Exception as e:
        logger.error(f"Firefox with GeckoDriver test failed: {e}")
        logger.info("Firefox with GeckoDriver test: FAILED ❌")
        return False

# ===== FIX FUNCTIONS =====

def fix_chrome_issues():
    """Fix common Chrome/Chromium issues"""
    chrome_path = find_browser('chrome')
    driver_path = find_driver('chromedriver')
    
    if not chrome_path:
        logger.error("Cannot fix Chrome: binary not found")
        return False
    
    # Create a symlink in /usr/local/bin if it's a snap installation
    if 'snap' in chrome_path and not os.path.exists('/usr/local/bin/chrome'):
        logger.info("Creating symlink for snap Chrome installation...")
        create_symlink(chrome_path, '/usr/local/bin/chrome')
    
    # Install required dependencies
    package_manager = get_package_manager()
    if package_manager in ['apt', 'apt-get']:
        deps = [
            "libnss3", "libgbm1", "libasound2", "libatk1.0-0", 
            "libatk-bridge2.0-0", "libcups2", "libdrm2", "libxkbcommon0",
            "libxcomposite1", "libxdamage1", "libxfixes3", "libxrandr2",
            "libglib2.0-0", "libpango-1.0-0", "libcairo2"
        ]
        
        logger.info(f"Installing Chrome dependencies using {package_manager}...")
        cmd = ['sudo', package_manager, 'install', '-y'] + deps
        result = run_command(cmd)
        
        if result['success']:
            logger.info("Dependencies installed successfully")
        else:
            logger.warning(f"Failed to install dependencies: {result['stderr']}")
    
    # Download ChromeDriver if missing or incompatible
    if not driver_path:
        logger.info("ChromeDriver not found. Attempting to download...")
        
        # Get Chrome version
        chrome_version_result = run_command([chrome_path, '--version'])
        if chrome_version_result['success']:
            version_str = chrome_version_result['stdout'].strip()
            # Extract major version (e.g., "Google Chrome 91.0.4472.114" -> "91")
            try:
                major_version = version_str.split()[2].split('.')[0]
                logger.info(f"Chrome major version: {major_version}")
                
                # Download matching ChromeDriver
                tmp_dir = tempfile.mkdtemp()
                download_cmd = [
                    'wget', '-q', f'https://chromedriver.storage.googleapis.com/LATEST_RELEASE_{major_version}',
                    '-O', f'{tmp_dir}/version.txt'
                ]
                result = run_command(download_cmd)
                
                if result['success']:
                    with open(f'{tmp_dir}/version.txt', 'r') as f:
                        exact_version = f.read().strip()
                    
                    logger.info(f"Downloading ChromeDriver version {exact_version}...")
                    download_url = f"https://chromedriver.storage.googleapis.com/{exact_version}/chromedriver_linux64.zip"
                    
                    download_cmd = ['wget', '-q', download_url, '-O', f'{tmp_dir}/chromedriver.zip']
                    result = run_command(download_cmd)
                    
                    if result['success']:
                        # Extract and install
                        extract_cmd = ['unzip', '-q', f'{tmp_dir}/chromedriver.zip', '-d', tmp_dir]
                        result = run_command(extract_cmd)
                        
                        if result['success']:
                            # Make executable and move to /usr/local/bin
                            chromedriver_path = os.path.join(tmp_dir, 'chromedriver')
                            os.chmod(chromedriver_path, os.stat(chromedriver_path).st_mode | stat.S_IEXEC)
                            
                            move_cmd = ['sudo', 'mv', chromedriver_path, '/usr/local/bin/chromedriver']
                            result = run_command(move_cmd)
                            
                            if result['success']:
                                logger.info("ChromeDriver installed successfully to /usr/local/bin/chromedriver")
                            else:
                                logger.error(f"Failed to move ChromeDriver: {result['stderr']}")
                        else:
                            logger.error(f"Failed to extract ChromeDriver: {result['stderr']}")
                    else:
                        logger.error(f"Failed to download ChromeDriver: {result['stderr']}")
                else:
                    logger.error(f"Failed to get ChromeDriver version: {result['stderr']}")
                    
                # Clean up
                shutil.rmtree(tmp_dir, ignore_errors=True)
                
            except Exception as e:
                logger.error(f"Failed to parse Chrome version: {e}")
        else:
            logger.error(f"Failed to get Chrome version: {chrome_version_result['stderr']}")
    
    return True

def fix_firefox_issues():
    """Fix common Firefox issues"""
    firefox_path = find_browser('firefox')
    driver_path = find_driver('geckodriver')
    
    if not firefox_path:
        logger.error("Cannot fix Firefox: binary not found")
        return False
    
    # Create a symlink in /usr/local/bin if it's a snap installation
    if 'snap' in firefox_path and not os.path.exists('/usr/local/bin/firefox'):
        logger.info("Creating symlink for snap Firefox installation...")
        create_symlink(firefox_path, '/usr/local/bin/firefox')
    
    # Install required dependencies
    package_manager = get_package_manager()
    if package_manager in ['apt', 'apt-get']:
        deps = [
            "libgtk-3-0", "libdbus-glib-1-2", "libxt6", "xvfb"
        ]
        
        logger.info(f"Installing Firefox dependencies using {package_manager}...")
        cmd = ['sudo', package_manager, 'install', '-y'] + deps
        result = run_command(cmd)
        
        if result['success']:
            logger.info("Dependencies installed successfully")
        else:
            logger.warning(f"Failed to install dependencies: {result['stderr']}")
    
    # Download GeckoDriver if missing
    if not driver_path:
        logger.info("GeckoDriver not found. Attempting to download...")
        
        # Get latest GeckoDriver version
        tmp_dir = tempfile.mkdtemp()
        
        try:
            import requests
            response = requests.get('https://api.github.com/repos/mozilla/geckodriver/releases/latest')
            release_data = response.json()
            latest_version = release_data['tag_name']
            
            logger.info(f"Latest GeckoDriver version: {latest_version}")
            
            # Find Linux 64-bit asset
            for asset in release_data['assets']:
                if 'linux64' in asset['name']:
                    download_url = asset['browser_download_url']
                    
                    logger.info(f"Downloading GeckoDriver from {download_url}...")
                    download_cmd = ['wget', '-q', download_url, '-O', f'{tmp_dir}/geckodriver.tar.gz']
                    result = run_command(download_cmd)
                    
                    if result['success']:
                        # Extract and install
                        extract_cmd = ['tar', '-xzf', f'{tmp_dir}/geckodriver.tar.gz', '-C', tmp_dir]
                        result = run_command(extract_cmd)
                        
                        if result['success']:
                            # Make executable and move to /usr/local/bin
                            geckodriver_path = os.path.join(tmp_dir, 'geckodriver')
                            os.chmod(geckodriver_path, os.stat(geckodriver_path).st_mode | stat.S_IEXEC)
                            
                            move_cmd = ['sudo', 'mv', geckodriver_path, '/usr/local/bin/geckodriver']
                            result = run_command(move_cmd)
                            
                            if result['success']:
                                logger.info("GeckoDriver installed successfully to /usr/local/bin/geckodriver")
                            else:
                                logger.error(f"Failed to move GeckoDriver: {result['stderr']}")
                        else:
                            logger.error(f"Failed to extract GeckoDriver: {result['stderr']}")
                    else:
                        logger.error(f"Failed to download GeckoDriver: {result['stderr']}")
                    
                    break
        except Exception as e:
            logger.error(f"Failed to download GeckoDriver: {e}")
        
        # Clean up
        shutil.rmtree(tmp_dir, ignore_errors=True)
    
    return True

# ===== MAIN FUNCTION =====

def main():
    """Main function"""
    logger.info("Starting browser diagnostic...")
    
    # System information
    logger.info(f"System: {platform.system()}")
    logger.info(f"Release: {platform.release()}")
    logger.info(f"Distribution: {platform.platform()}")
    logger.info(f"Python version: {sys.version}")
    
    try:
        # Check for Selenium
        import selenium
        logger.info(f"Selenium version: {selenium.__version__}")
    except ImportError:
        logger.error("Selenium is not installed. Install using: pip install selenium")
        logger.info("Installing Selenium...")
        result = run_command([sys.executable, '-m', 'pip', 'install', 'selenium'])
        if result['success']:
            logger.info("Selenium installed successfully")
            try:
                import selenium
                logger.info(f"Selenium version: {selenium.__version__}")
            except ImportError:
                logger.error("Failed to import Selenium after installation")
        else:
            logger.error(f"Failed to install Selenium: {result['stderr']}")
    
    # Check for browsers and drivers
    chrome_path = find_browser('chrome')
    firefox_path = find_browser('firefox')
    chromedriver_path = find_driver('chromedriver')
    geckodriver_path = find_driver('geckodriver')
    
    logger.info("\n=== BROWSER STATUS SUMMARY ===")
    logger.info(f"Chrome/Chromium: {'✅ Found' if chrome_path else '❌ Not found'}")
    logger.info(f"Firefox: {'✅ Found' if firefox_path else '❌ Not found'}")
    logger.info(f"ChromeDriver: {'✅ Found' if chromedriver_path else '❌ Not found'}")
    logger.info(f"GeckoDriver: {'✅ Found' if geckodriver_path else '❌ Not found'}")
    
    # Test browsers with drivers
    chrome_success = False
    firefox_success = False
    
    if chrome_path and chromedriver_path:
        chrome_success = test_chrome_with_driver()
    
    if firefox_path and geckodriver_path:
        firefox_success = test_firefox_with_driver()
    
    # Fix browser issues if needed
    if not chrome_success and (chrome_path or chromedriver_path):
        logger.info("\n=== FIXING CHROME/CHROMIUM ISSUES ===")
        fix_chrome_issues()
        # Retest after fixing
        if chrome_path and find_driver('chromedriver'):
            chrome_success = test_chrome_with_driver()
    
    if not firefox_success and (firefox_path or geckodriver_path):
        logger.info("\n=== FIXING FIREFOX ISSUES ===")
        fix_firefox_issues()
        # Retest after fixing
        if firefox_path and find_driver('geckodriver'):
            firefox_success = test_firefox_with_driver()
    
    # Final report
    logger.info("\n=== FINAL RESULTS ===")
    logger.info(f"Chrome/Chromium with ChromeDriver: {'✅ Working' if chrome_success else '❌ Not working'}")
    logger.info(f"Firefox with GeckoDriver: {'✅ Working' if firefox_success else '❌ Not working'}")
    
    if not chrome_success and not firefox_success:
        logger.info("\n=== RECOMMENDATIONS ===")
        logger.info("Neither Chrome nor Firefox are working properly with Selenium.")
        
        if not chrome_path and not firefox_path:
            logger.info("1. Install at least one browser:")
            logger.info("   - For Chrome/Chromium: sudo apt install chromium-browser")
            logger.info("   - For Firefox: sudo apt install firefox")
        
        if not chromedriver_path and chrome_path:
            logger.info("2. Install ChromeDriver:")
            logger.info("   - Download matching version from https://chromedriver.chromium.org/downloads")
            logger.info("   - Extract and move to /usr/local/bin with: sudo mv chromedriver /usr/local/bin/")
        
        if not geckodriver_path and firefox_path:
            logger.info("3. Install GeckoDriver:")
            logger.info("   - Download from https://github.com/mozilla/geckodriver/releases")
            logger.info("   - Extract and move to /usr/local/bin with: sudo mv geckodriver /usr/local/bin/")
        
        logger.info("4. Install dependencies:")
        logger.info("   - For Chrome: sudo apt install libnss3 libgbm1 libasound2")
        logger.info("   - For Firefox: sudo apt install libgtk-3-0 libdbus-glib-1-2")
        
        logger.info("5. If using snap packages, create symlinks:")
        logger.info("   - Chrome: sudo ln -s /snap/bin/chromium /usr/local/bin/chrome")
        logger.info("   - Firefox: sudo ln -s /snap/bin/firefox /usr/local/bin/firefox")
        
        logger.info("\nAfter making changes, run this script again to verify.")
    else:
        logger.info("\n=== GOOD NEWS! ===")
        if chrome_success:
            logger.info("✅ Chrome/Chromium is working correctly with Selenium!")
        if firefox_success:
            logger.info("✅ Firefox is working correctly with Selenium!")

if __name__ == "__main__":
    main() 
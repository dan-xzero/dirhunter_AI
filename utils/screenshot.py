# File: dirhunter_ai/utils/screenshot.py (parallel version)
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def get_chrome_version():
    """Get the current Chrome browser version"""
    try:
        # For macOS
        result = subprocess.run([
            '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '--version'
        ], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version = result.stdout.strip().split()[-1]
            return version
    except:
        pass
    
    # Alternative method
    try:
        result = subprocess.run(['google-chrome', '--version'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version = result.stdout.strip().split()[-1]
            return version
    except:
        pass
    
    return None

def setup_chrome_driver():
    """Setup Chrome driver using system ChromeDriver"""
    try:
        chrome_version = get_chrome_version()
        if chrome_version:
            print(f"[i] Chrome version detected: {chrome_version}")
        
        # Use system chromedriver (already updated to match Chrome version)
        service = Service('/opt/homebrew/bin/chromedriver')
        return service
    except Exception as e:
        print(f"[!] Failed to setup ChromeDriver: {e}")
        return None

# ─────────── single screenshot ───────────
def take_screenshot(url, output_path):
    driver = None
    try:
        # Setup Chrome options
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1280,800")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-plugins")
        chrome_options.add_argument("--disable-images")  # Faster loading
        chrome_options.add_argument("--disable-javascript")  # Faster loading
        chrome_options.add_argument("--user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")
        
        # Setup driver service
        service = setup_chrome_driver()
        if service is None:
            raise Exception("Could not setup ChromeDriver")
        
        # Create driver
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.set_page_load_timeout(30)
        driver.implicitly_wait(10)
        
        # Navigate and take screenshot
        driver.get(url)
        
        # Wait a moment for page to load
        try:
            WebDriverWait(driver, 5).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
        except:
            pass  # Continue even if body not found
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Take screenshot
        driver.save_screenshot(output_path)
        print(f"[✔] Screenshot saved: {output_path}")
        
    except Exception as e:
        print(f"[!] Screenshot failed for {url}: {e}")
        
        # Try to provide helpful error messages
        if "session not created" in str(e).lower():
            print(f"[!] ChromeDriver compatibility issue detected.")
            print(f"[!] Try running: brew upgrade chromedriver")
        elif "chromedriver" in str(e).lower():
            print(f"[!] ChromeDriver not found or not executable.")
            print(f"[!] Try installing: brew install chromedriver")
        elif "timeout" in str(e).lower():
            print(f"[!] Page load timeout - the site might be slow or unresponsive.")
        
    finally:
        if driver:
            try:
                driver.quit()
            except:
                pass

# ─────────── parallel runner ───────────
def take_screenshots_parallel(task_list, max_workers=3):
    """
    task_list = [ { 'url': ..., 'output_path': ... }, ... ]
    Reduced max_workers to prevent ChromeDriver conflicts
    """
    print(f"[i] Taking {len(task_list)} screenshots with {max_workers} workers...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(take_screenshot, t['url'], t['output_path']) for t in task_list]
        completed = 0
        
        for future in as_completed(futures):
            try:
                future.result()
                completed += 1
                print(f"[i] Screenshot progress: {completed}/{len(task_list)}")
            except Exception as e:
                print(f"[!] Parallel screenshot task failed: {e}")
                completed += 1
"""Screenshot capture utility – now degrades gracefully when *selenium* is not installed.

If the import of the *selenium* package fails, we set the flag `_SELENIUM_AVAILABLE = False` and
simply skip all screenshot work rather than crashing the whole application.  This allows
`main_optimized.py` to run in environments where screenshots are disabled or the dependency is
missing.  A concise console message explains how to enable the feature.
"""

# File: dirhunter_ai/utils/screenshot.py (parallel version)
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ─── Optional Selenium import (graceful degradation) ───────────────────────────
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    _SELENIUM_AVAILABLE = True
except ImportError:  # pragma: no cover – env without selenium
    _SELENIUM_AVAILABLE = False

    # Stub objects so that type checkers and runtime attribute access do not fail.
    class _MissingDep:
        """Placeholder that safely absorbs attribute access and calls when selenium is absent."""
        def __getattr__(self, _):
            return self  # Return self for chained access

        def __call__(self, *_, **__):
            return self  # Callable that returns self

        def __bool__(self):
            return False  # Evaluate to False in boolean context

    from typing import Any as _Any

    _missing = _MissingDep()

    # Explicitly type as `Any` so static analysers don't complain about later calls.
    webdriver: _Any
    Options: _Any
    Service: _Any
    By: _Any
    WebDriverWait: _Any
    EC: _Any

    webdriver = Options = Service = By = WebDriverWait = EC = _missing  # type: ignore

    print("[!] Selenium package is not installed – screenshots will be skipped. "
          "Run 'pip install -r requirements.txt' to enable screenshot support.")

# stdlib
import shutil
import platform
from typing import Optional

import threading  # NEW: for concurrency control
import time  # NEW: for time.sleep

MAX_CONCURRENT_CHROME = int(os.getenv("MAX_CONCURRENT_CHROME", "3"))  # NEW: configurable cap
_chrome_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_CHROME)  # NEW

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

def _find_chromedriver_path() -> Optional[str]:
    """Return a valid *chromedriver* binary path if one is present on the host."""

    # Explicit env override allows the user to point to any custom path
    env_override = os.getenv("CHROMEDRIVER_PATH")
    if env_override and os.path.exists(env_override):
        return env_override

    system = platform.system().lower()

    # A set of common installation paths across OSes
    candidate_paths: list[str] = []

    if system == "darwin":  # macOS
        candidate_paths += [
            "/opt/homebrew/bin/chromedriver",        # Homebrew (Apple Silicon)
            "/usr/local/bin/chromedriver",          # Homebrew (Intel)
        ]
    elif system == "linux":
        candidate_paths += [
            "/usr/bin/chromedriver",                # Debian/Ubuntu package
            "/usr/local/bin/chromedriver",          # Manual install
            "/snap/bin/chromedriver",               # Snap install
        ]
    elif system == "windows":
        candidate_paths += [
            os.path.join(os.getenv("PROGRAMFILES", "C:\\Program Files"), "ChromeDriver", "chromedriver.exe"),
            os.path.join(os.getenv("PROGRAMFILES(X86)", "C:\\Program Files (x86)"), "ChromeDriver", "chromedriver.exe"),
        ]

    # Anything discoverable on PATH via shutil.which / where
    which_driver = shutil.which("chromedriver")
    if which_driver:
        candidate_paths.insert(0, which_driver)  # Highest priority

    for path in candidate_paths:
        if path and os.path.exists(path) and os.access(path, os.X_OK):
            return path

    return None


def setup_chrome_driver():
    """Return a *Service* for a local ChromeDriver binary, or *None* if none is found."""

    driver_path = _find_chromedriver_path()
    if driver_path:
        print(f"[i] Using local ChromeDriver at: {driver_path}")
        return Service(driver_path)

    # Nothing found – Selenium Manager will handle download
    print("[i] No local ChromeDriver found; Selenium Manager will attempt to download one on the fly.")
    return None


def chromedriver_available() -> bool:
    """Public helper for callers/tests to quickly check driver availability."""
    return _find_chromedriver_path() is not None

# ─────────── single screenshot ───────────
def take_screenshot(url, output_path):
    """Take a screenshot of a URL, with robust fallback mechanisms"""
    if not _SELENIUM_AVAILABLE:
        print(f"[i] Skipping screenshot for {url} – selenium not installed.")
        try:
            from utils.screenshot_fallback import create_placeholder_screenshot
            create_placeholder_screenshot(url, output_path)
            print(f"[✓] Created placeholder screenshot for {url}")
        except ImportError:
            print(f"[!] Screenshot fallback not available for {url}")
        return
        
    # NEW: throttle concurrent Chrome launches
    if not _chrome_semaphore.acquire(timeout=60):
        print("[!] Could not acquire Chrome semaphore (timeout)")
        try:
            from utils.screenshot_fallback import create_placeholder_screenshot
            create_placeholder_screenshot(url, output_path)
            print(f"[✓] Created placeholder screenshot after semaphore timeout")
        except ImportError:
            print(f"[!] Screenshot fallback not available after semaphore timeout")
        return
        
    driver = None
    success = False
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Try multiple Chrome configurations
    for attempt, config in enumerate(_get_chrome_configs(), 1):
        if success:
            break
            
        try:
            print(f"[i] Screenshot attempt {attempt} for {url}")
            driver = _create_chrome_driver(config)
            if not driver:
                continue
                
            driver.set_page_load_timeout(30)
            print(f"[i] Navigating to {url}...")
            driver.get(url)
            
            # If Chrome shows SSL interstitial, attempt auto-bypass
            try:
                page_source_lower = driver.page_source.lower()
                if ("your connection is not private" in page_source_lower or
                    "net::err_cert" in page_source_lower):
                    body_el = driver.find_element(By.TAG_NAME, "body")
                    body_el.send_keys("thisisunsafe")
                    # give it a moment to navigate
                    time.sleep(2)
            except Exception:
                pass
            
            # Wait a moment for page to load
            try:
                WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.TAG_NAME, "body"))
                )
            except:
                pass  # Continue even if body not found
            
            # Take screenshot
            driver.save_screenshot(output_path)
            print(f"[✔] Screenshot saved: {output_path}")
            success = True
            
            # Capture page text content for JS-rendered pages
            try:
                page_text = driver.execute_script("return document.body.innerText || '';")
            except Exception:
                page_text = ''
                
            text_path = output_path.rsplit('.', 1)[0] + '.txt'
            if page_text.strip():
                with open(text_path, 'w', encoding='utf-8') as tp:
                    tp.write(page_text)
                print(f"[i] Page text saved: {text_path}")
            else:
                # create empty file to signal capture attempt
                open(text_path, 'w').close()
                
        except Exception as e:
            print(f"[!] Screenshot attempt {attempt} failed: {e}")
            # Continue to next configuration
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass
            # Clean up temp directory if used
            if config.get('temp_dir'):
                try:
                    import shutil
                    shutil.rmtree(config['temp_dir'], ignore_errors=True)
                except Exception:
                    pass
    
    # If all attempts failed, use fallback
    if not success:
        print(f"[!] All screenshot attempts failed for {url}")
        try:
            from utils.screenshot_fallback import create_placeholder_screenshot
            create_placeholder_screenshot(url, output_path)
            print(f"[✓] Created placeholder screenshot after all attempts failed")
        except ImportError:
            print(f"[!] Screenshot fallback not available after failed attempts")
    
    # Always release the semaphore
    _chrome_semaphore.release()


def _get_chrome_configs():
    """Get list of Chrome configurations to try"""
    configs = []
    
    # Config 1: No user data directory
    configs.append({
        'options': [
            "--headless",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--window-size=1280,800",
            "--disable-extensions",
            "--disable-plugins",
            "--disable-images",
            "--disable-javascript"
        ],
        'capabilities': {
            'acceptInsecureCerts': True
        }
    })
    
    # Config 2: With unique user data directory
    import tempfile
    import uuid
    temp_dir = os.path.join(tempfile.gettempdir(), f"chrome_temp_{uuid.uuid4().hex}")
    os.makedirs(temp_dir, exist_ok=True)
    
    configs.append({
        'options': [
            "--headless",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu", 
            "--window-size=1280,800",
            "--disable-extensions",
            "--disable-plugins",
            "--disable-images",
            "--disable-javascript",
            f"--user-data-dir={temp_dir}"
        ],
        'capabilities': {
            'acceptInsecureCerts': True
        },
        'temp_dir': temp_dir
    })
    
    # Config 3: Minimal config with incognito
    configs.append({
        'options': [
            "--headless",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--incognito"
        ],
        'capabilities': {}
    })
    
    return configs


def _create_chrome_driver(config):
    """Create a Chrome driver with the given configuration"""
    try:
        chrome_options = Options()
        
        # Add options
        for option in config.get('options', []):
            chrome_options.add_argument(option)
        
        # Add capabilities
        for key, value in config.get('capabilities', {}).items():
            chrome_options.set_capability(key, value)
        
        # Try with service first
        try:
            service = setup_chrome_driver()
            if service:
                return webdriver.Chrome(service=service, options=chrome_options)
        except Exception:
            pass
            
        # Fall back to direct initialization
        return webdriver.Chrome(options=chrome_options)
        
    except Exception as e:
        print(f"[!] Failed to create Chrome driver: {e}")
        return None

# ─────────── pre-filtering ───────────
def filter_screenshot_tasks(findings):
    """Pre-filter findings to reduce screenshot workload"""
    if not findings:
        return []
    
    # Group by hash to avoid screenshotting identical pages
    hash_groups = defaultdict(list)
    for f in findings:
        if f.get('body_hash'):
            hash_groups[f['body_hash']].append(f)
        else:
            # No hash, include it
            hash_groups[f['url']].append(f)
    
    # Take only one screenshot per unique hash
    filtered = []
    for hash_val, group in hash_groups.items():
        # Prefer findings with keywords in URL
        priority_keywords = ['admin', 'config', 'api', 'login', 'dashboard', 'upload']
        sorted_group = sorted(group, 
                            key=lambda x: any(kw in x['url'].lower() for kw in priority_keywords),
                            reverse=True)
        
        # Take the first (highest priority) finding from each hash group
        representative = sorted_group[0]
        filtered.append(representative)
        
        # Mark others as having same content
        for other in sorted_group[1:]:
            other['screenshot_duplicate_of'] = representative['url']
    
    print(f"[i] Screenshot filtering: {len(findings)} findings → {len(filtered)} unique pages")
    return filtered

# ─────────── parallel runner ───────────
def take_screenshots_parallel(task_list, max_workers=3):
    if not _SELENIUM_AVAILABLE:
        print("[i] Selenium not installed – skipping all screenshot tasks.")
        return
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
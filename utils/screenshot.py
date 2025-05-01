# File: dirhunter_ai/utils/screenshot.py (parallel version)
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# ─────────── single screenshot ───────────
def take_screenshot(url, output_path):
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_window_size(1280, 800)
        driver.get(url)
        driver.save_screenshot(output_path)
        driver.quit()
        print(f"[✔] Screenshot saved: {output_path}")
    except Exception as e:
        print(f"[!] Screenshot failed for {url}: {e}")

# ─────────── parallel runner ───────────
def take_screenshots_parallel(task_list, max_workers=5):
    """
    task_list = [ { 'url': ..., 'output_path': ... }, ... ]
    """
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(take_screenshot, t['url'], t['output_path']) for t in task_list]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"[!] Parallel screenshot task failed: {e}")
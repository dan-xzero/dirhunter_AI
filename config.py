# File: dirhunter_ai/config.py

# Path to your wordlist
WORDLIST = "wordlists/common.txt"

# Extensions to test (no dot prefix in ffuf)
EXTENSIONS = [".php", ".html", ".bak", ".env", ".zip", ".json"]

# Number of threads for ffuf
THREADS = 50

# Directories for output
SCREENSHOT_DIR = "results/screenshots"
RAW_RESULTS_DIR = "results/raw"

# File: dirhunter_ai/config.py

# Path to your wordlist
WORDLIST = "wordlists/common.txt"

# Extensions to test (no dot prefix in ffuf)
EXTENSIONS = [".php", ".html", ".bak", ".env", ".zip", ".json"]

# Number of threads for ffuf
THREADS = 50

# Slack Webhook URL (replace with your actual webhook)
WEBHOOK_URL = "https://hooks.slack.com/services/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"

# Directories for output
SCREENSHOT_DIR = "results/screenshots"
RAW_RESULTS_DIR = "results/raw"

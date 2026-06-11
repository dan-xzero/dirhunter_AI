# File: dirhunter_ai/config.py
import os

try:
    from dotenv import load_dotenv

    load_dotenv(override=True)
except ImportError:
    pass

# Path to your wordlist
WORDLIST = "wordlists/common.txt"

# Extensions to test (no dot prefix in ffuf)
EXTENSIONS = [".php", ".html", ".bak", ".env", ".zip", ".json"]

# Number of threads for ffuf
THREADS = 50

# Directories for output
SCREENSHOT_DIR = "results/screenshots"
RAW_RESULTS_DIR = "results/raw"

# Retention policy for cleanup (days)
CLEANUP_DAYS = 30

# Feature flags for the Postgres-backed portal migration.
USE_PG = os.getenv("USE_PG", "0").lower() in {"1", "true", "yes", "on"}
USE_LLM_VALIDATOR = os.getenv("USE_LLM_VALIDATOR", "0").lower() in {"1", "true", "yes", "on"}
USE_NEW_SLACK = os.getenv("USE_NEW_SLACK", "0").lower() in {"1", "true", "yes", "on"}
USE_LEGACY_HTML = os.getenv("USE_LEGACY_HTML", "1").lower() in {"1", "true", "yes", "on"}
KILL_BROWSER_SESSIONS = os.getenv("DIRHUNTER_KILL_BROWSER_SESSIONS", "1").lower() in {"1", "true", "yes", "on"}

# OpenAI model controls. Keep model IDs configurable so production can adopt
# newly released model aliases without code changes.
OPENAI_MODEL_VISION = os.getenv("OPENAI_MODEL_VISION", "gpt-5.5")
OPENAI_MODEL_VALIDATOR = os.getenv("OPENAI_MODEL_VALIDATOR", "gpt-5.5")
OPENAI_MODEL_FALLBACK = os.getenv("OPENAI_MODEL_FALLBACK", "gpt-5-mini")

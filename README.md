# DirHunter AI — Advanced Filtering & Reporting README

## 📦 Overview
DirHunter AI is an advanced Python-based fuzzing and filtering pipeline designed to:
✅ Discover hidden endpoints using FFUF  
✅ Filter out noise and false positives using heuristics, hashes, and content patterns  
✅ Classify high-signal findings using GPT-4 Vision  
✅ Log all actions with detailed skip/keep reasons and timestamps  
✅ Generate HTML reports and Slack alerts for actionable results

---

## 🏗 File Structure
```
dirhunter_ai/
├── config.py
├── domain.txt
├── main.py
├── utils/
│   ├── ai_analyzer.py
│   ├── db_handler.py
│   ├── filters.py
│   ├── reporter.py
│   ├── scanner.py
│   ├── screenshot.py
│   ├── slack_alert.py
└── db/
    └── endpoint_hashes.sqlite
└── logs/
    ├── skipped_YYYYMMDD_HHMM.txt
    ├── kept_YYYYMMDD_HHMM.txt
    └── summary_YYYYMMDD_HHMM.txt
```

---

## 🚀 How to Run
1️⃣ Prepare your `domain.txt` with one domain per line.

2️⃣ Run the main script:
```bash
python3 main.py
```

### Optional Flags
- `--ignore-hash` → Forces reprocessing of all endpoints (ignores DB hash cache)
- `--reset-db` → Clears the entire hash database (`endpoint_hashes.sqlite`)
- `--screenshot-workers <N>` → Sets number of parallel screenshot threads (default: 5)

Examples:
```bash
python3 main.py --ignore-hash
python3 main.py --reset-db
python3 main.py --screenshot-workers 10
```

---

## ⚙ Features
✅ FFUF scanning with:
- `-r` redirects
- `-fc 404,429` filtered codes
- configurable wordlists/extensions

✅ Advanced filtering:
- Heuristic: status + length + sensitive keywords
- Pattern skip: e.g., `/api/`, `/healthz`, `/status`
- Soft-404 detection via parallel curl
- Response body SHA-1 clustering
- Persistent DB for tracking endpoint changes

✅ Logging Enhancements:
- Skip/keep reasons logged with `[length-filter]`, `[curl-soft404]`, `[pattern-skip]`, `[hash-unchanged]`
- Timestamped logs for clear tracking
- Per-domain summary stats

✅ AI Classification:
- Uses GPT-4 Vision to assign one of 14 categories (Admin Panel, Login Panel, Secrets, etc.)
- Helps prioritize only the most critical findings

✅ Reporting:
- HTML grouped reports by tag
- Slack notifications for high-severity results

---

## 📂 Logs Explained
```
logs/
├── skipped_YYYYMMDD_HHMM.txt   # All skipped endpoints + reason
├── kept_YYYYMMDD_HHMM.txt      # All kept endpoints after filtering
└── summary_YYYYMMDD_HHMM.txt   # Summary stats per domain
```

## 📦 Database
- SQLite DB stores seen URLs + content hashes
- Skips unchanged endpoints on reruns (unless `--ignore-hash` is set)
- Reset with `--reset-db`

---

## 🔧 Requirements
- Python 3.8+
- FFUF installed and available in `$PATH`
- OpenAI API key set in environment (for Vision)
- curl installed
- ChromeDriver + Selenium for screenshots

---

## ✨ Roadmap
✅ Per-path heuristic skips  
✅ Soft-404 hash clustering  
✅ Parallel curl for speed  
✅ Persistent hash DB  
✅ Command-line flags for reset/force/thread control  
✅ Detailed logs + summaries  
✅ High-signal AI tagging  

Let me know if you want a Dockerfile, Makefile, or CI integration script next!

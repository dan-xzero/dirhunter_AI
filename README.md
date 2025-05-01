**README.md**
```
# DirHunter AI

An advanced AI-driven fuzzing, filtering, and reporting pipeline for endpoint discovery and analysis.

## Features
- ✨ FFUF-based fuzzing (with rate limits & retries)
- 🛡 Soft-404 filtering and heuristic exclusions
- 🔐 Hash-based change detection to reduce repeat noise
- ⚙ Parallelized screenshot capture
- 🧠 GPT-4 Vision tagging & category classification
- 🔍 Tag validation rules to auto-correct mislabels
- 📢 Slack integration for high-signal alerts
- 📄 HTML, CSV, and log report outputs

## Setup
1. Clone the repo:
   ```bash
   git clone https://github.com/yourname/dirhunter_ai.git
   cd dirhunter_ai
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure `.env` for your OpenAI and Slack webhook keys.

4. Provide your target domains in `domain.txt`.

## Usage
Run a full scan:
```bash
python main.py --screenshot-workers 5
```

To reset the hash DB:
```bash
python main.py --reset-db
```

To ignore existing hashes and force fresh scan:
```bash
python main.py --ignore-hash
```

## Project Layout
```
dirhunter_ai/
|-- main.py             # entry point
|-- config.py           # settings, API keys, paths
|-- utils/
|   |-- scanner.py      # FFUF runner
|   |-- filters.py      # soft-404, pattern, cluster filtering
|   |-- screenshot.py   # parallel screenshot module
|   |-- ai_analyzer.py  # GPT-4 Vision interface
|   |-- slack_alert.py  # Slack integration
|   |-- reporter.py     # HTML + summary reports
|   |-- db_handler.py   # SQLite hash DB
|   |-- tag_validator.py# rule-based tag corrections
|-- results/            # output screenshots, raw data
|-- logs/               # run logs + summaries
|-- wordlists/          # wordlists for fuzzing
|-- domain.txt          # list of domains to scan
|-- .env                # secrets + keys (excluded)
|-- .gitignore
|-- README.md
```

## Contribution
Pull requests welcome! Please open an issue first if making large changes.

## License
MIT License © 2025 Your Name
```


# 🔍 DirHunter AI – Advanced Security Discovery Platform

An intelligent AI-powered web security scanning platform that combines directory fuzzing, automated screenshot analysis, and comprehensive reporting with Slack integration.

---

## 🚀 Key Features

✅ **AI-Powered Analysis** - GPT-4 Vision automatically classifies findings into 16 security categories  
✅ **Intelligent Filtering** - Multi-stage filtering with fuzzy hashing to eliminate false positives  
✅ **Finding Status Tracking** - Tracks new, changed, and existing findings over time  
✅ **Consolidated Reporting** - Single dashboard view with detailed drill-down capabilities  
✅ **Rate Limit Handling** - Automatically detects and retries rate-limited paths  
✅ **Slack Integration** - Consolidated notifications with rich formatting  
✅ **Parallel Processing** - Configurable workers for screenshots and scanning  
✅ **Modern Dashboard** - Beautiful, responsive web interface with priority-based findings  
✅ **Tech Fingerprinting** - Fast regex plus Wappalyzer detection with outdated-version flag  
✅ **CVE Detection** - OSV.dev API checks package manifests for known vulnerabilities  
✅ **Auto Cleanup** - Old screenshots/raw JSON auto-purged after 30 days to save disk space  

---

## 🏗 Project Architecture

```
dirhunter_ai/
├── main_optimized.py       # Optimized CLI entry point with parallel scanning
├── slack_dirscan_app.py    # Enhanced Slack app with multi-domain support
├── config.py               # Configuration settings
├── utils/                 
│   ├── ai_analyzer.py      # Enhanced GPT-4 Vision with 16 categories
│   ├── db_handler.py       # SQLite with finding history & rate limit tracking
│   ├── filters.py          # Multi-stage filtering with status tracking
│   ├── reporter.py         # Modern dashboard and detailed reports
│   ├── scanner.py          # FFUF integration with rate limit detection
│   ├── screenshot.py       # Parallel Selenium screenshot capture
│   ├── slack_alert.py      # Consolidated Slack notifications
│   └── tag_validator.py    # AI classification validation
├── domains/               
│   ├── prod_domains.txt    # Production targets
│   └── nonprod_domains.txt # Development/testing targets
├── wordlists/             
│   ├── wordlist_prod.txt   # Production wordlist
│   └── wordlist_nonprod.txt # Comprehensive wordlist
├── results/               
│   ├── html/               # Dashboard and reports
│   ├── screenshots/        # Captured screenshots
│   └── raw/                # FFUF output
├── db/                    # SQLite databases
├── logs/                  # Scan logs and summaries
└── .env                   # Configuration secrets
```

---

## 🎯 AI Classification Categories

The system intelligently categorizes findings into 16 security-relevant categories:

**🔴 Critical Priority:**
- **Credentials/Secrets** - API keys, passwords, tokens, .env files
- **Database** - Database interfaces, phpMyAdmin, SQL tools

**🟠 High Priority:**
- **Admin Panel** - Administrative dashboards, control panels
- **Backup** - Backup files, archives, old versions
- **Source Code** - Exposed code, .git directories
- **Config/Environment** - Configuration files, settings

**🟡 Medium Priority:**
- **Logs/Debug** - Log files, debug output, stack traces
- **Login Panel** - Authentication forms, sign-in pages
- **Payment Info** - Payment forms, billing pages
- **PII/User Data** - Personal information, user profiles
- **Internal/Restricted** - Internal tools, staging environments

**🟢 Low Priority:**
- **API Documentation** - Swagger, API docs
- **Development/Test** - Test pages, development tools
- **E-commerce Page** - Product listings, shopping pages
- **404/NOT Found** - Error pages
- **Other** - Uncategorized findings

---

## ⚙ Prerequisites

- **Python 3.10+**
- **Node.js ≥ 18** (for Wappalyzer CLI)
- **Wappalyzer CLI** - Technology fingerprinting (`npm i -g @wappalyzer/cli`)
- **FFUF** - Fast web fuzzer (`brew install ffuf` or download from GitHub)
- **Chrome/Chromium** - For screenshot capture
- **Slack App** (optional) - For notifications and slash commands

> ℹ️ The project now uses the **official Wappalyzer CLI** instead of the deprecated Python package. Ensure the binary `wappalyzer` is in your `$PATH`.

> CVE look-ups are powered by the public **OSV.dev v1 API** – no key required.

---

## 🔧 Environment Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt

# Install Wappalyzer CLI (global)
npm i -g @wappalyzer/cli
```

Note: `ssdeep` is optional; if unavailable the fuzzy-hash logic falls back gracefully. To enable fuzzy duplicate detection install it via Homebrew (`brew install ssdeep`) or the provided helper:

```bash
chmod +x setup_ssdeep_env.sh
./setup_ssdeep_env.sh
```

### 2. Set up ssdeep (for fuzzy hashing)

```bash
chmod +x setup_ssdeep_env.sh
./setup_ssdeep_env.sh
```

### 3. Configure Environment

Create `.env` file:

```bash
# Slack Integration (optional)
SLACK_BOT_TOKEN=xoxb-your-bot-token
WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
SLACK_SIGNING_SECRET=your-signing-secret

# Report URLs
REPORT_BASE_URL=https://your-ngrok-or-server.com
NGROK_URL=https://your-ngrok-tunnel.ngrok.io

# CVE/Tech fingerprinting
WAPPALYZER_BINARY=/usr/local/bin/wappalyzer   # override if not in PATH

# AI Classification
OPENAI_API_KEY=sk-your-openai-api-key
```

### 4. Configure Domains

Edit domain lists:
- `domains/prod_domains.txt` - Production targets
- `domains/nonprod_domains.txt` - Development/testing targets

---

## 🧹 Cleanup Rotation

Results older than **30 days** are automatically deleted at the start of each `main_optimized.py` run. Adjust retention by editing `CLEANUP_DAYS` in `config.py`.

---

## 🏃 Usage

### CLI Commands

```bash
# Scan all configured domains
python main_optimized.py

# Scan specific domains
python main_optimized.py --domains example.com,test.com --wordlist wordlists/wordlist_nonprod.txt

# Show all findings (including existing ones)
python main_optimized.py --ignore-hash

# Retry rate-limited paths from previous scans
python main_optimized.py --retry-rate-limits

# Configure parallel workers
python main_optimized.py --screenshot-workers 10

# Reset database (start fresh)
python main_optimized.py --reset-db
# Parallel domain scanning
python main_optimized.py --parallel-domains 5 --screenshot-workers 10

# Generate performance report
python main_optimized.py --performance-report
```

### Slack Integration

#### 1. Start the Slack App

```bash
python slack_dirscan_app.py
```

#### 2. Expose via ngrok

```bash
ngrok http 31337
```

#### 3. Configure Slack App

Set your Slack app's slash command URL to:
```
https://your-ngrok-url.ngrok.io/slack/dirscan
```

#### 4. Slack Commands

```bash
# Scan specific domains
/dirscan example.com

# Scan multiple domains
/dirscan example.com,test.com --ignore-hash

# Scan all configured domains
/dirscan all

# Scan only production domains
/dirscan prod

# Scan only non-production domains
/dirscan nonprod

# Retry rate-limited paths
/dirscan all --retry-rate-limits

# Get help
/dirscan help

💡  Copy the *Signing Secret* from your Slack app and export it so the Flask app can verify requests:

```bash
export SLACK_SIGNING_SECRET='<your-signing-secret>'
```
```

---

## 📊 Dashboard & Reports

### Main Dashboard
Access the comprehensive dashboard at:
```
https://your-server.com/reports/dashboard.html
```

**Features:**
- 📈 High-level statistics across all domains
- 🚨 Priority-based security findings
- 📊 Category distribution charts
- 🌐 Domain-specific report links
- 📱 Mobile-responsive design

### Domain Reports
Individual domain reports with:
- 🏷️ Findings grouped by AI categories
- 🔄 Status indicators (new/changed/existing)
- 🖼️ Screenshot previews
- 📋 Detailed metadata

### Finding Status Indicators
- 🆕 **New** - First time discovered
- 🔄 **Changed** - Content modified since last scan
- ✓ **Existing** - Previously seen, unchanged

---

## 🤖 Slack Notifications

### Consolidated Alerts
Receive a single, comprehensive notification containing:

- 📊 **Summary Statistics** - Total domains, findings, status breakdown
- 🚨 **High Priority Findings** - Critical security issues with screenshots
- 📈 **Category Distribution** - Top finding categories
- 🔗 **Report Links** - Direct links to detailed reports

### Alert Features
- 🎯 **Priority-based highlighting** of critical findings
- 📸 **Screenshot thumbnails** for visual context
- 🏷️ **Status badges** for new/changed findings
- 📱 **Rich formatting** with emojis and structure

---

## 🛡 Security Features

### Rate Limit Handling
- **Automatic Detection** - Identifies 429 responses
- **Intelligent Retry** - Reduced rate retry with delays
- **Progress Tracking** - Database tracking of retry attempts
- **Resumable Scans** - Continue from where rate limiting occurred

### Finding Persistence
- **Historical Tracking** - Complete history of all findings
- **Change Detection** - Identifies when content changes
- **Deduplication** - SHA1 and fuzzy hash comparison
- **Trend Analysis** - Track finding patterns over time

### False Positive Reduction
- **Multi-stage Filtering** - Length, pattern, and content analysis
- **Soft 404 Detection** - Identifies disguised error pages
- **Fuzzy Hashing** - Eliminates near-duplicate content
- **Keyword Filtering** - Focus on security-relevant paths

---

## 🔧 Configuration

### Scanner Settings (`config.py`)
```python
EXTENSIONS = [".php", ".html", ".bak", ".env", ".zip", ".json"]
THREADS = 50
SCREENSHOT_DIR = "results/screenshots"
RAW_RESULTS_DIR = "results/raw"
```

### AI Classification Tuning (`utils/ai_analyzer.py`)
- Adjust category priorities
- Modify URL pattern matching
- Configure batch processing limits
- Set rate limiting for API calls

### Slack Customization (`utils/slack_alert.py`)
- Modify message formatting
- Adjust priority thresholds
- Configure alert frequency
- Customize dashboard links

---

## 📈 Performance Optimization

### Parallel Processing
- **Screenshot Workers** - Configurable Selenium instances
- **CURL Workers** - Parallel content fetching
- **AI Classification** - Batch processing with rate limits

### Resource Management
- **Database Indexing** - Optimized queries for large datasets
- **Memory Efficiency** - Streaming processing for large wordlists
- **Disk Usage** - Automatic cleanup of temporary files

### Scaling Considerations
- **Rate Limiting** - Respectful scanning with delays
- **Worker Pools** - Configurable concurrency limits
- **Error Recovery** - Graceful handling of failures

---

## 🔍 Troubleshooting

### Common Issues

**FFUF not found:**
```bash
brew install ffuf  # macOS
# or download from https://github.com/ffuf/ffuf
```

**Screenshot failures:**
```bash
# Install Chrome/Chromium
brew install --cask google-chrome
```

**OpenAI API errors:**
```bash
# Check API key in .env
export OPENAI_API_KEY=sk-your-key
```

**Rate limiting issues:**
```bash
# Use retry flag
python main_optimized.py --retry-rate-limits
```

### Logs and Debugging
- **Main log:** `dirhunter_ai.log`
- **Scan summaries:** `logs/summary_*.txt`
- **Skipped endpoints:** `logs/skipped_*.txt`
- **Kept endpoints:** `logs/kept_*.txt`

---

## 🤝 Contributing

We welcome contributions! Areas for improvement:

- 🎯 **New AI Categories** - Additional classification types
- 🔧 **Scanner Integrations** - Support for other tools
- 📊 **Dashboard Features** - Enhanced visualizations
- 🔌 **Platform Integration** - Discord, Teams, etc.
- 🚀 **Performance** - Optimization and scaling

---

## 📄 License

This project is for educational and authorized security testing purposes only. Users are responsible for compliance with applicable laws and regulations.

---

## 📞 Support

For issues, feature requests, or custom implementations:
- 📧 Create an issue on GitHub
- 💬 Join our community discussions
- 📖 Check the troubleshooting guide

---

**Happy Hunting! 🎯** 

---

## 🧪 Testing & Quick Start

1. Install dependencies (virtual-env recommended):

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# Optional fuzzy hashing
./setup_ssdeep_env.sh
```

2. Run a smoke test against example domains list:

```bash
python main_optimized.py --domains domains/prod_domains.txt --wordlist wordlists/wordlist_prod.txt --parallel-domains 3 --screenshot-workers 3 --performance-report
```

3. Open `results/html/dashboard.html` in your browser to review findings.

Logs and summaries are written to the `logs/` directory; use them to verify cleanup rotation and new CVE / tech badges in reports. 

---

## 🧪 Running Tests

The repository ships with a small pytest suite covering technology fingerprinting helpers and Slack CVE aggregation logic.

```bash
pytest -q
```

All tests should pass. Continuous integration pipelines can call this command to verify CVE handling remains stable.

---

## 🛡️ Technology Fingerprinting & CVE Visibility

1. **Wappalyzer CLI** scans each discovered URL and saves raw JSON to `results/wappalyzer_raw/`.
2. Detected `{name, version}` pairs are enriched with CVE data via [OSV.dev](https://osv.dev) batch queries.
3. The dashboard shows coloured CVE pills and a dedicated stat-card; finding pages include detailed, collapsible CVE tables.
4. Slack alerts summarise total CVEs, per-domain severities, and list the *top vulnerable packages*.

Severity levels are derived from the number of distinct CVEs for a package:

| Count | Severity |
|-------|----------|
| 1     | Low      |
| 2     | Medium   |
| 3-4   | High     |
| ≥5    | Critical |

This heuristic keeps the UI fast without requiring additional CVSS API calls. 


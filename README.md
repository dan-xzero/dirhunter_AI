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
✅ **Header Capture** - Captures and displays response headers for security analysis  
✅ **Auto Cleanup** - Old screenshots/raw JSON auto-purged after 30 days to save disk space  

---

## 🏗 Project Architecture

```
dirhunter_ai/
├── main_optimized.py       # Main production script with full functionality
├── scan_without_screenshots.py # Fast testing script (no screenshots)
├── slack_dirscan_app.py    # Production Slack app with web interface
├── config.py               # Configuration settings
├── utils/                 
│   ├── ai_analyzer.py      # GPT-4 Vision analysis with 16 categories
│   ├── db_handler.py       # SQLite with finding history & rate limit tracking
│   ├── filters.py          # Multi-stage filtering with status tracking
│   ├── enhanced_reporter.py # Enhanced HTML reporting
│   ├── reporter.py         # Basic dashboard and detailed reports
│   ├── scanner.py          # FFUF integration with rate limit detection
│   ├── screenshot.py       # Parallel Selenium screenshot capture
│   ├── slack_alert.py      # Consolidated Slack notifications
│   ├── enhanced_slack.py   # Enhanced Slack alerts with CVE data
│   ├── findings_enricher.py # Findings enrichment with headers
│   ├── fingerprint_manager.py # Technology fingerprinting
│   ├── tag_validator.py    # AI classification validation
│   ├── performance.py      # Performance tracking
│   ├── resource_manager.py # Resource optimization
│   ├── cleanup.py          # Automated cleanup operations
│   ├── rate_control.py     # Rate limiting management
│   ├── run_history.py      # Run history tracking
│   ├── dns_check.py        # DNS validation
│   └── [25 total utility modules]
├── domains/               
│   ├── prod_domains.txt    # Production targets
│   └── nonprod_domains.txt # Development/testing targets
├── wordlists/             
│   ├── wordlist_prod.txt   # Production wordlist
│   ├── wordlist_prod.txt.noslash # Production wordlist (no trailing slash)
│   └── wordlist_nonprod.txt # Comprehensive wordlist
├── results/               
│   ├── html/               # Dashboard and reports
│   ├── screenshots/        # Captured screenshots
│   ├── raw/                # FFUF output
│   └── enriched/           # Enriched findings with headers
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

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd dirhunter_ai

# Install Python dependencies
pip install -r requirements.txt

# Install Wappalyzer CLI
npm install -g @wappalyzer/cli

# Install FFUF
brew install ffuf  # macOS
# or download from: https://github.com/ffuf/ffuf/releases
```

### 2. Configuration

Create a `.env` file with your configuration:

```bash
# OpenAI API Key (required for AI analysis)
OPENAI_API_KEY=your_openai_api_key_here

# Slack Configuration (optional)
WEBHOOK_URL=your_slack_webhook_url
SLACK_SIGNING_SECRET=your_slack_signing_secret

# Report Base URL (for dashboard links)
REPORT_BASE_URL=https://your-domain.com
```

### 3. Domain Configuration

Add your target domains to the appropriate files:

```bash
# Production domains
echo "example.com" >> domains/prod_domains.txt

# Non-production domains  
echo "test.example.com" >> domains/nonprod_domains.txt
```

### 4. Running Scans

#### Full Production Scan (with screenshots and AI analysis)
```bash
python main_optimized.py
```

#### Fast Testing Scan (no screenshots)
```bash
python scan_without_screenshots.py
```

#### Custom Domain Scan
```bash
python main_optimized.py --domains example.com,test.com --wordlist wordlists/wordlist_prod.txt
```

#### Slack Integration
```bash
python slack_dirscan_app.py
# Access web interface at http://localhost:31337
```

---

## 📊 Output & Reports

### Dashboard
- **Location**: `results/html/dashboard.html`
- **Features**: Consolidated view of all findings with priority-based sorting

### Detailed Reports
- **Findings Report**: `results/html/{domain}_findings.html`
- **Tags Report**: `results/html/{domain}_tags.html`
- **Screenshots**: `results/screenshots/{domain}/`

### Slack Notifications
- Real-time scan progress updates
- Critical finding alerts
- Consolidated results with rich formatting

---

## 🔧 Advanced Configuration

### Performance Tuning
```bash
# Adjust parallel processing
python main_optimized.py --screenshot-workers 5 --parallel-domains 3

# Fast filtering mode
python main_optimized.py --fast-filter

# Resource optimization
python main_optimized.py --optimize-resources
```

### Rate Limit Handling
```bash
# Retry previously rate-limited paths
python main_optimized.py --retry-rate-limits
```

### Database Management
```bash
# Reset database (start fresh)
python main_optimized.py --reset-db
```

---

## 🛠 Troubleshooting

### Common Issues

**Screenshot Failures**
- Ensure Chrome/Chromium is installed
- Check Xvfb availability (Linux)
- Verify webdriver-manager installation

**AI Analysis Issues**
- Verify OpenAI API key in `.env`
- Check API quota and billing
- Ensure internet connectivity

**FFUF Errors**
- Verify FFUF installation: `ffuf -version`
- Check wordlist file permissions
- Ensure target domains are accessible

**Slack Integration**
- Verify webhook URL and signing secret
- Check ngrok tunnel for local development
- Ensure proper Slack app permissions

---

## 📈 Performance Metrics

The system tracks comprehensive performance metrics:
- **Scan Duration**: Total time per domain
- **Screenshot Performance**: Parallel processing efficiency
- **AI Analysis Speed**: Classification processing time
- **Filtering Effectiveness**: False positive reduction rates
- **Resource Usage**: Memory and CPU utilization

---

## 🔒 Security Features

- **Header Analysis**: Captures and displays security headers
- **CVE Detection**: Automatic vulnerability scanning
- **Secret Scanning**: Detects exposed credentials and tokens
- **Technology Fingerprinting**: Identifies outdated components
- **Rate Limit Protection**: Prevents target overload

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

## 📞 Support

For issues and questions:
- Create an issue on GitHub
- Check the troubleshooting section
- Review the logs in `logs/` directory

---

*Built with ❤️ for the security community* 


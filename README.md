# 📘 DirHunter AI – README

An advanced AI-powered fuzzing + reporting tool that integrates with Slack, sends threaded alerts, and serves live HTML reports (via ngrok or your server).

---

## 🚀 Features

✅ AI screenshot tagging (via GPT-4 Vision)  
✅ High-signal filtering (hash + heuristics)  
✅ Parallel screenshot workers  
✅ Slack `/dirscan` slash command  
✅ Threaded Slack replies on scan completion  
✅ Live HTML reports + screenshot server  
✅ Background DB tracking (only alerts on new/changed findings)

---

## 🏗 Project Layout

```
dirhunter_ai/
├── main.py                 # main CLI entry
├── slack_dirscan_app.py    # Flask Slack app (slash command handler)
├── config.py               # config (wordlist, dirs)
├── utils/                 
│   ├── ai_analyzer.py      # GPT-4 Vision tagging
│   ├── db_handler.py       # hash DB
│   ├── filters.py          # filtering + clustering
│   ├── reporter.py         # HTML report generator
│   ├── scanner.py          # FFUF runner
│   ├── screenshot.py       # parallel Selenium screenshots
│   ├── slack_alert.py      # Slack grouped alerts
│   └── tag_validator.py    # tag rule enforcement
├── wordlists/             
│   └── common.txt          # fuzzing wordlist
├── results/               
│   ├── html/               # generated reports
│   └── screenshots/        # captured screenshots
├── logs/                  
│   └── *.txt               # run summaries + skipped lists
├── .env                   # secrets + config
└── README.md
```

---

## ⚙ Prerequisites

- Python 3.10+
- `ffuf` installed and available in `$PATH`
- Slack app with:
  - Bot Token (`SLACK_BOT_TOKEN`)
  - Slash Command (`/dirscan`)
  - Permissions: `chat:write`, `commands`

---

## 🔧 Environment Setup

Create `.env`:

```
SLACK_BOT_TOKEN=xoxb-...
WEBHOOK_URL=https://hooks.slack.com/services/...
REPORT_BASE_URL=https://<your-ngrok-or-server>
NGROK_URL=https://<your-ngrok>
```

Install requirements:

```
pip install -r requirements.txt
```

---

## 🏃 Running CLI

```
python main.py --domains domain.txt --ignore-hash --screenshot-workers 10
```

Or single domain:

```
python main.py --domains example.com
```

---

## 🤖 Running Slack Slash Command

1️⃣ Run the Flask app:

```
python slack_dirscan_app.py
```

2️⃣ Expose it via ngrok:

```
ngrok http 31337
```

3️⃣ Configure your Slack app `/dirscan` to point to:

```
https://<ngrok>/slack/dirscan
```

4️⃣ In Slack:

```
/dirscan example.com --ignore-hash --screenshot-workers 10
```

✅ It replies immediately: "Fuzzing started..."  
✅ Once complete, posts results in a thread.

---

## 📊 Reports

- Accessible at:
  
```
https://<ngrok>/reports/<domain>.html
```

- Screenshots served at:

```
https://<ngrok>/screenshots/<image>
```

---

## 🛡 Permissions Needed

Slack Bot:

- `chat:write`
- `commands`

Make sure your bot is installed in the workspace and has access to the channels you want to use.

---

## ❤️ Contributing

Feel free to suggest improvements, add new AI tagging categories, or submit PRs for integration with other platforms (Discord, Teams, etc.)!

---

## 📬 Contact

If you need help or want custom setups, reach out to the maintainer.


# File: slack_dirscan_app.py

import os
import subprocess
import threading
import argparse
import requests
from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv

load_dotenv(override=True)

SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
SCAN_SCRIPT = "python main.py"
REPORTS_DIR = "results/html"
SCREENSJOT_DIR = "results/screenshots"
NGROK_URL = os.getenv("NGROK_URL", "http://localhost:5000")

app = Flask(__name__)

HELP_MESSAGE = (
    "📘 *DirHunter AI Slash Command Help*\n\n"
    "*Usage:*\n"
    "`/dirscan <domain> [options]`\n\n"
    "*Examples:*\n"
    "`/dirscan example.com --ignore-hash --screenshot-workers 10`\n\n"
    "*Available options:*\n"
    "`--ignore-hash` → Ignore stored hash DB\n"
    "`--reset-db` → Reset the hash database\n"
    "`--screenshot-workers N` → Number of parallel screenshot workers (default: 5)`\n\n"
    "This command triggers a full fuzzing scan on the specified domain and will report results back here when complete."
)

# ─────────── scan runner ───────────

def get_wordlist_type(domain):
    with open("domains/prod_domains.txt") as f:
        prod_domains = {d.strip() for d in f if d.strip()}
    return "prod" if domain in prod_domains else "nonprod"

def run_scan_async(domain, args, response_url, base_url):
    domain_type = get_wordlist_type(domain)
    wordlist_arg = f"--wordlist wordlists/wordlist_{domain_type}.txt"

    cmd = f"{SCAN_SCRIPT} --domains {domain} {wordlist_arg} {args}"
    print(f"[~] Launching scan: {cmd}")
    subprocess.call(cmd, shell=True)

    report_url = f"{base_url}/reports/{domain}_tags.html"
    followup_message = {
        "response_type": "in_channel",
        "text": f"✅ Scan complete for *{domain}*! View the full report: {report_url}"
    }
    try:
        resp = requests.post(response_url, json=followup_message)
        if resp.status_code != 200:
            print(f"[!] Failed to send follow-up Slack message: {resp.text}")
        else:
            print(f"[+] Follow-up Slack message sent for {domain}")
    except Exception as e:
        print(f"[!] Error sending follow-up Slack message: {e}")

# ─────────── Slack endpoint ───────────
@app.route("/slack/dirscan", methods=["POST"])
def slack_dirscan():
    text = request.form.get("text", "").strip()
    response_url = request.form.get("response_url")

    if text in ["help", "--help"]:
        return jsonify({"response_type": "ephemeral", "text": HELP_MESSAGE})

    parts = text.split()
    if not parts:
        return jsonify({"response_type": "ephemeral", "text": "❌ Please provide a domain."})

    domain = parts[0]
    extra_args = " ".join(parts[1:])

    threading.Thread(target=run_scan_async, args=(domain, extra_args, response_url, NGROK_URL)).start()

    return jsonify({"response_type": "in_channel", "text": f"✅ Fuzzing started for *{domain}*! Results will be posted here when ready."})

# ─────────── Serve Reports ───────────
@app.route("/reports/<path:filename>", methods=["GET"])
def serve_report(filename):
    return send_from_directory(REPORTS_DIR, filename)

@app.route("/screenshots/<path:filename>", methods=["GET"])
def serve_screenshots(filename):
    return send_from_directory(SCREENSJOT_DIR, filename)

# ─────────── Main ───────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 31337)), debug=True)

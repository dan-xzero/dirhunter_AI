# File: slack_dirscan_app.py

import os
import subprocess
import threading
import argparse
import requests
from flask import Flask, request, jsonify, send_from_directory
from dotenv import load_dotenv
import sys
import hmac
import hashlib
import time

load_dotenv(override=True)

SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")
SCAN_SCRIPT = f"{sys.executable} main_optimized.py"
REPORTS_DIR = "results/html"
SCREENSHOT_DIR = "results/screenshots"
NGROK_URL = os.getenv("NGROK_URL", "http://localhost:5000")

app = Flask(__name__)

HELP_MESSAGE = (
    "📘 *DirHunter AI Slash Command Help*\n\n"
    "*Usage:*\n"
    "`/dirscan <domain(s)> [options]`\n\n"
    "*Examples:*\n"
    "`/dirscan example.com`\n"
    "`/dirscan example.com,test.com --ignore-hash`\n"
    "`/dirscan all` - Scan all configured domains\n"
    "`/dirscan prod` - Scan production domains only\n"
    "`/dirscan nonprod` - Scan non-production domains only\n\n"
    "*Available options:*\n"
    "`--ignore-hash` → Show all findings including existing ones\n"
    "`--screenshot-workers N` → Number of parallel screenshot workers (default: 5)\n"
    "`--retry-rate-limits` → Retry previously rate-limited paths\n\n"
    "*Reports:*\n"
    f"Dashboard: `{NGROK_URL}/reports/dashboard.html`\n\n"
    "This command triggers a full fuzzing scan and will report results back here when complete."
)

# ─────────── scan runner ───────────

def get_wordlist_for_domain(domain):
    """Determine which wordlist to use based on domain configuration"""
    try:
        with open("domains/prod_domains.txt") as f:
            prod_domains = {d.strip() for d in f if d.strip()}
        return "wordlists/wordlist_prod.txt" if domain in prod_domains else "wordlists/wordlist_nonprod.txt"
    except:
        return "wordlists/wordlist_nonprod.txt"

def verify_slack_request(req):
    """Validate request using Slack signing secret. Returns True if valid or no secret configured."""
    if not SLACK_SIGNING_SECRET:
        return True  # Skip verification if secret not provided

    timestamp = req.headers.get("X-Slack-Request-Timestamp")
    slack_signature = req.headers.get("X-Slack-Signature")

    if not timestamp or not slack_signature:
        return False

    # Reject if request is too old (replay attack protection)
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False

    sig_basestring = f"v0:{timestamp}:{req.get_data(as_text=True)}"
    my_signature = "v0=" + hmac.new(
        SLACK_SIGNING_SECRET.encode(), sig_basestring.encode(), hashlib.sha256
    ).hexdigest()

    # Constant-time compare
    return hmac.compare_digest(my_signature, slack_signature)

def run_scan_async(domains, args, response_url, base_url):
    """Run scan for multiple domains and send consolidated results"""
    
    # Build command based on domain specification
    if domains.lower() == "all":
        # Scan all configured domains
        cmd = f"{SCAN_SCRIPT} {args}"
    elif domains.lower() == "prod":
        # Scan production domains only
        with open("domains/prod_domains.txt") as f:
            prod_list = [d.strip() for d in f if d.strip()]
        if not prod_list:
            requests.post(response_url, json={"response_type": "ephemeral", "text": "❌ No production domains configured."})
            return
        cmd = f"{SCAN_SCRIPT} --domains {','.join(prod_list)} --wordlist wordlists/wordlist_prod.txt {args}"
    elif domains.lower() == "nonprod":
        # Scan non-production domains only
        with open("domains/nonprod_domains.txt") as f:
            nonprod_list = [d.strip() for d in f if d.strip()]
        if not nonprod_list:
            requests.post(response_url, json={"response_type": "ephemeral", "text": "❌ No non-production domains configured."})
            return
        cmd = f"{SCAN_SCRIPT} --domains {','.join(nonprod_list)} --wordlist wordlists/wordlist_nonprod.txt {args}"
    else:
        # Specific domains provided
        domain_list = [d.strip() for d in domains.split(",")]
        
        # Group domains by wordlist type
        prod_domains = []
        nonprod_domains = []
        
        for domain in domain_list:
            wordlist = get_wordlist_for_domain(domain)
            if "prod" in wordlist:
                prod_domains.append(domain)
            else:
                nonprod_domains.append(domain)
        
        # For mixed domain types, we need to determine the best approach
        if prod_domains and nonprod_domains:
            # Use nonprod wordlist for all (more comprehensive)
            cmd = f"{SCAN_SCRIPT} --domains {domains} --wordlist wordlists/wordlist_nonprod.txt {args}"
        elif prod_domains:
            cmd = f"{SCAN_SCRIPT} --domains {domains} --wordlist wordlists/wordlist_prod.txt {args}"
        else:
            cmd = f"{SCAN_SCRIPT} --domains {domains} --wordlist wordlists/wordlist_nonprod.txt {args}"

    print(f"[~] Launching scan: {cmd}")
    
    # Run the scan
    result = subprocess.call(cmd, shell=True)
    
    # Prepare follow-up message
    dashboard_url = f"{base_url}/reports/dashboard.html"
    
    if result == 0:
        followup_message = {
            "response_type": "in_channel",
            "text": f"✅ Scan complete! View the comprehensive dashboard: {dashboard_url}\n\nThe consolidated results have been posted to the main channel."
        }
    else:
        followup_message = {
            "response_type": "in_channel",
            "text": f"⚠️ Scan completed with warnings. Check the dashboard for details: {dashboard_url}"
        }
    
    try:
        resp = requests.post(response_url, json=followup_message)
        if resp.status_code != 200:
            print(f"[!] Failed to send follow-up Slack message: {resp.text}")
        else:
            print(f"[+] Follow-up Slack message sent")
    except Exception as e:
        print(f"[!] Error sending follow-up Slack message: {e}")

# ─────────── Slack endpoint ───────────
@app.route("/slack/dirscan", methods=["POST"])
def slack_dirscan():
    # Validate request authenticity
    if not verify_slack_request(request):
        return jsonify({"error": "invalid request"}), 400

    text = request.form.get("text", "").strip()
    response_url = request.form.get("response_url")
    user_name = request.form.get("user_name", "User")

    if text in ["help", "--help", ""]:
        return jsonify({"response_type": "ephemeral", "text": HELP_MESSAGE})

    parts = text.split()
    if not parts:
        return jsonify({"response_type": "ephemeral", "text": "❌ Please provide domain(s) to scan or use 'all', 'prod', or 'nonprod'."})

    domains = parts[0]
    extra_args = " ".join(parts[1:])

    # Start scan in background thread
    threading.Thread(target=run_scan_async, args=(domains, extra_args, response_url, NGROK_URL)).start()

    # Determine what's being scanned for the immediate response
    if domains.lower() == "all":
        scan_target = "all configured domains"
    elif domains.lower() == "prod":
        scan_target = "production domains"
    elif domains.lower() == "nonprod":
        scan_target = "non-production domains"
    elif "," in domains:
        domain_count = len(domains.split(","))
        scan_target = f"{domain_count} domains"
    else:
        scan_target = domains

    return jsonify({
        "response_type": "in_channel", 
        "text": f"🚀 *{user_name}* started fuzzing scan for *{scan_target}*!\n\nResults will be posted here when ready. This may take several minutes depending on the number of domains and paths."
    })

# ─────────── Serve Reports ───────────
@app.route("/reports/<path:filename>", methods=["GET"])
def serve_report(filename):
    return send_from_directory(REPORTS_DIR, filename)

@app.route("/screenshots/<path:filename>", methods=["GET"])
def serve_screenshots(filename):
    return send_from_directory(SCREENSHOT_DIR, filename)

@app.route("/", methods=["GET"])
def index():
    """Simple index page with link to dashboard"""
    return f"""
    <html>
    <head>
        <title>DirHunter AI</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                   margin: 40px; text-align: center; }}
            h1 {{ color: #667eea; }}
            a {{ color: #6366f1; text-decoration: none; font-size: 1.2em; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <h1>🔍 DirHunter AI</h1>
        <p>Advanced Security Scanning Platform</p>
        <p><a href="/reports/dashboard.html">View Security Dashboard →</a></p>
    </body>
    </html>
    """

# ─────────── Main ───────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 31337)), debug=True)

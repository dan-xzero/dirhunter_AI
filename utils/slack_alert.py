import requests
import os
from dotenv import load_dotenv

load_dotenv(override=True)
REPORT_BASE_URL = os.getenv("REPORT_BASE_URL")

def send_slack_alert(domain, findings, webhook_url):
    """
    Always sends a Slack message with total + report link, even if no high-signal findings.
    """
    total = len(findings)
    high_signal_count = sum(1 for f in findings if f["ai_tag"] not in ["Other", "Unknown"])

    report_link = f"{REPORT_BASE_URL}/reports/{domain}_tags.html"
    title = f"🗂 Scan Results for {domain}"
    color = "#439FE0"  # Blue

    summary = (
        f"*Total findings:* {total}\n"
        f"*High-signal findings:* {high_signal_count}\n"
        f"📊 <{report_link}|View full report>"
    )

    payload = {
        "attachments": [
            {
                "fallback": f"Report ready for {domain}",
                "color": color,
                "title": title,
                "text": summary,
            }
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code != 200:
            print(f"[!] Slack alert failed: {response.text}")
        else:
            print(f"[+] Slack alert sent for {domain}")
    except Exception as e:
        print(f"[!] Slack alert error: {e}")

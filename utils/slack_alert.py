# File: dirhunter_ai/utils/slack_alert.py

import requests

# Make this configurable later
REPORT_BASE_URL = "https://reports.example.com"

def send_slack_alert(domain, findings, webhook_url):
    """
    Sends one grouped Slack message for all new/changed high-signal findings on a domain.
    """
    if not findings:
        return

    title = f"🚨 New/Updated Findings on {domain}"
    color = "#36a64f"  # Green for new/changed

    fields = []
    for f in findings:
        fields.append({
            "title": f"{f['ai_tag']} ({f['status']})",
            "value": f"<{f['url']}|{f['url']}>",
            "short": False
        })

    report_link = f"{REPORT_BASE_URL}/{domain}.html"

    payload = {
        "attachments": [
            {
                "fallback": f"New findings on {domain}",
                "color": color,
                "title": title,
                "fields": fields,
                "footer": f"📊 <{report_link}|View full report>",
            }
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code != 200:
            print(f"[!] Slack alert failed: {response.text}")
        else:
            print(f"[+] Slack alert sent for {domain} with {len(findings)} findings")
    except Exception as e:
        print(f"[!] Slack alert error: {e}")

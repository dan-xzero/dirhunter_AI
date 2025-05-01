# File: dirhunter_ai/utils/slack_alert.py

import requests

def send_slack_alert(finding, webhook_url):
    """
    Sends a formatted Slack message for high-signal findings.
    """
    title = f"🚨 High-Signal Finding Detected"
    color = "#e01e5a"

    payload = {
        "attachments": [
            {
                "fallback": f"High-Signal Finding: {finding['url']}",
                "color": color,
                "title": title,
                "fields": [
                    {"title": "URL", "value": finding["url"], "short": False},
                    {"title": "Status", "value": str(finding["status"]), "short": True},
                    {"title": "Length", "value": str(finding["length"]), "short": True},
                    {"title": "AI Label", "value": finding.get("ai_tag", "Unknown"), "short": True}
                ],
                "footer": "DirHunter AI",
            }
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code != 200:
            print(f"[!] Slack alert failed: {response.text}")
        else:
            print(f"[+] Slack alert sent: {finding['url']}")
    except Exception as e:
        print(f"[!] Slack alert error: {e}")

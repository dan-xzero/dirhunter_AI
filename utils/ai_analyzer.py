# File: dirhunter_ai/utils/ai_analyzer.py

import os
import base64
from openai import OpenAI
from PIL import Image

client = OpenAI()

def classify_screenshot_with_gpt(screenshot_path):
    """
    Classifies the screenshot into EXACTLY ONE category:
      1) Credentials/Secrets → tokens, passwords, keys, .env
      2) Database → DB tools, dumps, SQL interfaces
      3) Backup → .bak files, archive backups, old snapshots
      4) Logs/Debug → logs, debug traces, error outputs
      5) Config/Environment → config files, environment variables, settings dumps
      6) Source Code → visible code, version control, git/svn
      7) Admin Panel → admin dashboard, privileged management UI (NOT API docs)
      8) Login Panel → email/password or user login forms
      9) Payment Info → payment forms, credit card fields, invoices
      10) PII/User Data → personal data, profiles, user records
      11) Internal/Restricted → intranet, staging, labeled internal-only
      12) E-commerce Page → product listings, store front pages
      13) 404/NOT Found → 404 or not found pages
      14) Other → none of the above
    """

    try:
        with open(screenshot_path, "rb") as img:
            base64_image = base64.b64encode(img.read()).decode("utf-8")

        prompt_text = (
            "You are an expert website security AI helping classify screenshots. "
            "Look carefully at the screenshot and classify it into EXACTLY ONE of the following categories, "
            "choosing strictly based on the visible page content, not file names or guesses. "
            "Be strict and avoid overgeneralizing (e.g., do NOT call API docs an admin panel).\n\n"
            "Categories:\n"
            "1) Credentials/Secrets → tokens, passwords, keys, .env\n"
            "2) Database → DB tools, dumps, SQL interfaces\n"
            "3) Backup → .bak files, archive backups, old snapshots\n"
            "4) Logs/Debug → logs, debug traces, error outputs\n"
            "5) Config/Environment → config files, environment variables, settings dumps\n"
            "6) Source Code → visible code, version control, git/svn\n"
            "7) Admin Panel → admin dashboard, privileged management UI (NOT API docs)\n"
            "8) Login Panel → email/password or user login forms\n"
            "9) Payment Info → payment forms, credit card fields, invoices\n"
            "10) PII/User Data → personal data, profiles, user records\n"
            "11) Internal/Restricted → intranet, staging, labeled internal-only\n"
            "12) E-commerce Page → product listings, store front pages\n"
            "13) 404/NOT Found → 404 or not found pages\n"
            "14) Other → none of the above\n\n"
            "Respond ONLY with the category name as listed above — no extra text, no explanations."
        )

        response = client.chat.completions.create(
            model="gpt-4.1-mini",  # update to latest Vision model if available
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt_text},
                        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{base64_image}"}}
                    ]
                }
            ],
            max_tokens=20,
            temperature=0  # strict, deterministic classification
        )

        classification = response.choices[0].message.content.strip()

        valid_categories = {
            "Credentials/Secrets", "Database", "Backup", "Logs/Debug",
            "Config/Environment", "Source Code", "Admin Panel", "Login Panel",
            "Payment Info", "PII/User Data", "Internal/Restricted", "E-commerce Page", "404/NOT Found", "Other"
        }

        if classification not in valid_categories:
            print(f"[!] Unknown classification returned: {classification}")
            return "Other"

        return classification

    except Exception as e:
        print(f"[!] GPT vision classification failed: {e}")
        return "Unknown"

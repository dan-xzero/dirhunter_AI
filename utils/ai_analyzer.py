# File: dirhunter_ai/utils/ai_analyzer.py

import os
import base64
from openai import OpenAI
from PIL import Image
from dotenv import load_dotenv
import json

load_dotenv(override=True)
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY not found in environment!")

client = OpenAI(api_key=api_key)

# Enhanced categories with priority levels
CATEGORY_PRIORITY = {
    "Credentials/Secrets": 10,
    "Database": 9,
    "Admin Panel": 8,
    "Backup": 8,
    "Source Code": 7,
    "Config/Environment": 7,
    "Logs/Debug": 6,
    "Login Panel": 5,
    "Payment Info": 5,
    "PII/User Data": 5,
    "Internal/Restricted": 4,
    "API Documentation": 3,
    "Development/Test": 3,
    "E-commerce Page": 2,
    "404/NOT Found": 1,
    "Other": 0
}

def classify_screenshot_with_gpt(screenshot_path, url_context=None):
    """
    Enhanced classification with URL context and better prompting.
    Now includes additional categories and uses URL for better context.
    """

    try:
        with open(screenshot_path, "rb") as img:
            base64_image = base64.b64encode(img.read()).decode("utf-8")

        # Enhanced prompt with URL context
        prompt_text = (
            "You are an expert website security AI helping classify screenshots for vulnerability assessment. "
            "Analyze the screenshot carefully and classify it into EXACTLY ONE category based on security relevance.\n\n"
        )
        
        if url_context:
            prompt_text += f"URL Context: {url_context}\n\n"
        
        prompt_text += (
            "Categories (in order of security priority):\n"
            "1) Credentials/Secrets → visible passwords, API keys, tokens, .env files, private keys\n"
            "2) Database → database interfaces, phpMyAdmin, SQL tools, database dumps\n"
            "3) Admin Panel → administrative dashboards, control panels, management interfaces\n"
            "4) Backup → backup files, archives (.zip, .tar, .gz), old versions, snapshots\n"
            "5) Source Code → exposed source code, .git directories, version control\n"
            "6) Config/Environment → configuration files, settings, environment variables\n"
            "7) Logs/Debug → log files, debug output, stack traces, error details\n"
            "8) Login Panel → authentication forms, sign-in pages (NOT admin panels)\n"
            "9) Payment Info → payment forms, credit card fields, billing pages\n"
            "10) PII/User Data → personal information, user profiles, private data\n"
            "11) Internal/Restricted → internal tools, staging environments, restricted access\n"
            "12) API Documentation → Swagger, API docs, endpoint documentation\n"
            "13) Development/Test → test pages, development tools, debug interfaces\n"
            "14) E-commerce Page → product listings, shopping pages (without payment)\n"
            "15) 404/NOT Found → error pages, not found pages\n"
            "16) Other → none of the above\n\n"
            "Consider both the visual content AND the URL path when classifying.\n"
            "Respond ONLY with the category name exactly as listed above."
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Using latest vision model
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt_text},
                        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{base64_image}"}}
                    ]
                }
            ],
            max_tokens=30,
            temperature=0  # Deterministic classification
        )

        message_content = response.choices[0].message.content
        classification = message_content.strip() if message_content else "Other"

        # Validate classification
        if classification not in CATEGORY_PRIORITY:
            print(f"[!] Unknown classification returned: {classification}")
            return "Other"

        return classification

    except Exception as e:
        print(f"[!] GPT vision classification failed: {e}")
        return "Unknown"


def classify_by_url_pattern(url):
    """
    Quick classification based on URL patterns as a fallback or enhancement
    """
    url_lower = url.lower()
    
    # High priority patterns
    if any(pattern in url_lower for pattern in ['.env', 'api_key', 'secret', 'password', 'token']):
        return "Credentials/Secrets"
    if any(pattern in url_lower for pattern in ['phpmyadmin', 'adminer', 'database', '/db/']):
        return "Database"
    if any(pattern in url_lower for pattern in ['/admin', '/administrator', '/manage', '/panel']):
        return "Admin Panel"
    if any(pattern in url_lower for pattern in ['.bak', '.backup', '.old', '.zip', '.tar', '.gz']):
        return "Backup"
    if any(pattern in url_lower for pattern in ['.git', '.svn', 'source', '/src/']):
        return "Source Code"
    if any(pattern in url_lower for pattern in ['config', '.conf', 'settings']):
        return "Config/Environment"
    if any(pattern in url_lower for pattern in ['.log', 'debug', 'trace', 'error']):
        return "Logs/Debug"
    if any(pattern in url_lower for pattern in ['/login', '/signin', '/auth']):
        return "Login Panel"
    if any(pattern in url_lower for pattern in ['swagger', 'api-doc', '/api/v']):
        return "API Documentation"
    if any(pattern in url_lower for pattern in ['/test', '/dev', 'staging']):
        return "Development/Test"
    
    return None


def get_category_priority(category):
    """Get the security priority of a category (higher = more critical)"""
    return CATEGORY_PRIORITY.get(category, 0)


def batch_classify_screenshots(screenshot_tasks, max_workers=3):
    """
    Classify multiple screenshots in parallel with rate limiting
    Returns: dict mapping screenshot_path -> classification
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import time
    
    results = {}
    
    def classify_single(task):
        screenshot_path = task['screenshot_path']
        url = task.get('url', '')
        
        # Try URL pattern first for efficiency
        url_classification = classify_by_url_pattern(url)
        
        # Use GPT vision for verification or if URL pattern doesn't match
        gpt_classification = classify_screenshot_with_gpt(screenshot_path, url)
        
        # If URL pattern matches and has higher priority, use it
        if url_classification and get_category_priority(url_classification) >= get_category_priority(gpt_classification):
            return screenshot_path, url_classification
        
        return screenshot_path, gpt_classification
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        
        for i, task in enumerate(screenshot_tasks):
            # Rate limiting - add delay between submissions
            if i > 0 and i % 10 == 0:
                time.sleep(1)
            
            future = executor.submit(classify_single, task)
            futures.append(future)
        
        for future in as_completed(futures):
            try:
                path, classification = future.result()
                results[path] = classification
            except Exception as e:
                print(f"[!] Classification failed: {e}")
    
    return results

# File: dirhunter_ai/utils/ai_analyzer.py

import os
import base64
from openai import OpenAI
from PIL import Image
from dotenv import load_dotenv
import json
import logging

# Set up logger
logger = logging.getLogger(__name__)

load_dotenv(override=True)
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    logger.warning("OPENAI_API_KEY not found in environment - AI analysis features will be disabled")
    OPENAI_AVAILABLE = False
else:
    OPENAI_AVAILABLE = True
client = OpenAI(api_key=api_key)

# Enhanced categories with priority levels
CATEGORY_PRIORITY = {
    "Credentials/Secrets": 10,
    "Database": 9,
    "Admin Panel": 8,
    "Backup": 8,
    "Downloadable File": 6,
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

def analyze_security_posture(domain, findings, tech_data, headers_data):
    """
    Analyze security posture of a domain using AI
    
    Args:
        domain: Domain name
        findings: List of findings
        tech_data: Dictionary with technology data
        headers_data: Dictionary with headers data
    
    Returns:
        Dictionary with security posture assessment
    """
    if not OPENAI_AVAILABLE:
        logger.warning("OpenAI API not available. Skipping security posture analysis.")
        return {
            "risk_rating": "Unknown",
            "risk_score": "?/10",
            "summary": "Security posture analysis requires OpenAI API access.",
            "recommendations": ["Enable OpenAI API access to analyze security posture."],
            "cve_summary": "No data available",
            "cves": [],
            "missing_headers": []
        }
    
    try:
        # Extract finding categories
        finding_categories = {}
        for finding in findings:
            category = finding.get("ai_tag", "Other")
            if category not in finding_categories:
                finding_categories[category] = 0
            finding_categories[category] += 1
        
        # Extract CVE details
        cve_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        cve_details = []
        for finding in findings:
            tech = finding.get("tech", {})
            if tech and isinstance(tech, dict) and "cve_details" in tech:
                for pkg_name, details in tech["cve_details"].items():
                    if isinstance(details, dict) and "ids" in details:
                        severity = details.get("severity", "Medium")
                        severity_lower = severity.lower()
                        
                        if "critical" in severity_lower:
                            cve_counts["critical"] += len(details["ids"])
                        elif "high" in severity_lower:
                            cve_counts["high"] += len(details["ids"])
                        elif "medium" in severity_lower:
                            cve_counts["medium"] += len(details["ids"])
                        else:
                            cve_counts["low"] += len(details["ids"])
                        
                        for cve_id in details["ids"]:
                            cve_details.append({
                                "id": cve_id,
                                "package": pkg_name,
                                "version": details.get("version", "unknown"),
                                "severity": severity
                            })
        
        # Extract tech stack
        tech_stack = []
        for finding in findings:
            if "tech" in finding and isinstance(finding["tech"], dict):
                tech = finding["tech"]
                for tech_name, tech_info in tech.items():
                    if tech_name in ["cve_vulns", "cve_details"]:
                        continue
                    
                    version = ""
                    if isinstance(tech_info, dict) and "version" in tech_info:
                        version = tech_info["version"]
                    
                    tech_entry = {"name": tech_name, "version": version}
                    if tech_entry not in tech_stack:
                        tech_stack.append(tech_entry)
        
        # Collect all headers from findings
        all_headers = {}
        for finding in findings:
            if "headers" in finding and isinstance(finding["headers"], dict):
                for header_name, header_value in finding["headers"].items():
                    all_headers[header_name.lower()] = header_value
        
        # Check for security headers (case-insensitive check)
        security_headers = {
            "Content-Security-Policy": False,
            "X-Content-Type-Options": False,
            "X-Frame-Options": False,
            "X-XSS-Protection": False,
            "Strict-Transport-Security": False,
            "Referrer-Policy": False,
            "Permissions-Policy": False
        }
        
        for header_name in all_headers:
            header_lower = header_name.lower()
            if "content-security-policy" in header_lower:
                security_headers["Content-Security-Policy"] = True
            elif "x-content-type-options" in header_lower:
                security_headers["X-Content-Type-Options"] = True
            elif "x-frame-options" in header_lower:
                security_headers["X-Frame-Options"] = True
            elif "x-xss-protection" in header_lower:
                security_headers["X-XSS-Protection"] = True
            elif "strict-transport-security" in header_lower:
                security_headers["Strict-Transport-Security"] = True
            elif "referrer-policy" in header_lower:
                security_headers["Referrer-Policy"] = True
            elif "permissions-policy" in header_lower or "feature-policy" in header_lower:
                security_headers["Permissions-Policy"] = True
        
        # Get list of missing security headers
        missing_headers = [header for header, present in security_headers.items() if not present]
        
        # Build the prompt for GPT analysis
        prompt = f"""
As a security expert, analyze the following data for the domain {domain}:

FINDINGS CATEGORIES:
{json.dumps(finding_categories, indent=2)}

CVE COUNTS:
{json.dumps(cve_counts, indent=2)}

TECH STACK:
{json.dumps(tech_stack, indent=2)}

MISSING SECURITY HEADERS:
{json.dumps(missing_headers, indent=2)}

PRESENT SECURITY HEADERS:
{json.dumps([header for header, present in security_headers.items() if present], indent=2)}

Based on this data, provide a detailed security posture assessment in JSON format with the following structure:
{{
  "risk_rating": "Choose one: [LOW, MEDIUM, HIGH, CRITICAL]",
  "risk_score": "A score from 1-10 (e.g., '7/10')",
  "summary": "A concise paragraph summarizing the security posture focusing on actual issues found",
  "recommendations": ["List 3-4 specific, actionable security recommendations based only on the MISSING headers and other actual issues"],
  "cve_summary": "A brief statement about CVEs found (if any)"
}}

Consider:
1. The MISSING security headers only (DO NOT recommend adding headers that are already present)
2. The technology stack and identified vulnerabilities
3. Number and severity of CVEs
4. Specific missing security controls

Only provide recommendations for things that are actually missing or problematic.
Make the assessment objective, technical, and directly actionable.
"""
        
        # Call OpenAI API for analysis
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert analyzing website security postures. Focus only on actual issues found and don't invent problems. Only recommend implementing headers that are actually missing."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"}
        )
        
        # Parse the response
        try:
            result = json.loads(response.choices[0].message.content)
            
            # Ensure the result has all expected fields
            if not all(key in result for key in ["risk_rating", "risk_score", "summary", "recommendations", "cve_summary"]):
                raise ValueError("Missing required fields in AI response")
            
            # Normalize risk rating and score format
            result["risk_rating"] = result["risk_rating"].upper()
            if not "/" in result["risk_score"]:
                result["risk_score"] = f"{result['risk_score']}/10"
                
            # Add CVE details
            result["cves"] = cve_details
            
            # Add missing headers list
            result["missing_headers"] = missing_headers
                
            return result
            
        except json.JSONDecodeError:
            logger.error("Failed to parse OpenAI response as JSON")
            raise
            
    except Exception as e:
        logger.error(f"Error analyzing security posture: {e}")
        return {
            "risk_rating": "UNKNOWN",
            "risk_score": "?/10",
            "summary": f"Error analyzing security posture: {str(e)}",
            "recommendations": ["Contact support for assistance with security analysis."],
            "cve_summary": "No data available",
            "cves": [],
            "missing_headers": []
}

def classify_screenshot_with_gpt(screenshot_path, url_context=None, page_text=None):
    """
    Enhanced classification with URL context and better prompting.
    Now includes additional categories and uses URL for better context.
    """
    
    if not OPENAI_AVAILABLE:
        return "Other"

    try:
        with open(screenshot_path, "rb") as img:
            base64_image = base64.b64encode(img.read()).decode("utf-8")

        # Refined prompt – *no* URL context included to avoid bias
        prompt_text = (
            "You are an expert security analyst. Your task is to classify a WEB PAGE strictly based on its VISIBLE "
            "content (what a human user sees rendered in the browser). Absolutely IGNORE any address-bar text, "
            "file names, URLs, or query-parameters – they are unreliable. Only visual elements such as headings, "
            "forms, logos, buttons, tables, error messages, etc., should influence your decision.\n\n"
        )

        # Append visible page text if available (helps JS-rendered pages)
        if page_text:
            prompt_text += "Visible Page Text (may aid classification):\n" + page_text[:1000] + "\n\n"
        
        prompt_text += (
            "Categories (in order of security priority):\n"
            "1) Credentials/Secrets → visible passwords, API keys, tokens, .env files, private keys\n"
            "2) Database → database interfaces, phpMyAdmin, SQL tools, database dumps\n"
            "3) Admin Panel → administrative dashboards, control panels, management interfaces\n"
            "4) Backup → backup files, archives (.zip, .tar, .gz), old versions, snapshots\n"
            "5) Downloadable File → generic downloadable binary/file dialog (.zip, .sql, .bin, etc.)\n"
            "6) Source Code → exposed source code, .git directories, version control\n"
            "7) Config/Environment → configuration files, settings, environment variables\n"
            "8) Logs/Debug → log files, debug output, stack traces, error details\n"
            "9) Login Panel → authentication forms, sign-in pages (NOT admin panels)\n"
            "10) Payment Info → payment forms, credit card fields, billing pages\n"
            "11) PII/User Data → personal information, user profiles, private data\n"
            "12) Internal/Restricted → internal tools, staging environments, restricted access\n"
            "13) API Documentation → Swagger, API docs, endpoint documentation\n"
            "14) Development/Test → test pages, development tools, debug interfaces\n"
            "15) E-commerce Page → product listings, shopping pages (without payment)\n"
            "16) 404/NOT Found → error pages, not found pages\n"
            "17) Other → none of the above\n\n"
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
        page_text = task.get('page_text')
        
        # Try URL pattern first for efficiency
        url_classification = classify_by_url_pattern(url)
        
        # Use GPT vision for verification or if URL pattern doesn't match
        gpt_classification = classify_screenshot_with_gpt(screenshot_path, url_context=url, page_text=page_text)
        
        # Prefer GPT vision. Use URL pattern ONLY if GPT returns ambiguous low-priority result.
        if url_classification and gpt_classification in {"Other", "404/NOT Found", "Unknown"}:
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

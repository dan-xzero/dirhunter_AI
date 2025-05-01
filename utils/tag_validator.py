# File: dirhunter_ai/utils/tag_validator.py

TAG_RULES = {
    "Admin Panel": {
        "must_contain": ["/admin", "adminpanel", "administrator"],
        "must_not_contain": ["api-doc", "apidocs", "swagger"],
        "min_status": 200,
        "max_status": 403
    },
    "Login Panel": {
        "must_contain": ["login", "signin", "auth"],
        "must_not_contain": ["api", "docs"],
        "min_status": 200,
        "max_status": 403
    },
    "Database": {
        "must_contain": ["db", "database", "sql", "phpmyadmin"],
        "must_not_contain": ["apidoc", "docs"],
        "min_status": 200,
        "max_status": 403
    },
    "Backup": {
        "must_contain": [".bak", ".zip", ".tar", ".gz"],
        "must_not_contain": ["backup.js", "backup.json"],
        "min_status": 200,
        "max_status": 403
    },
    "Credentials/Secrets": {
        "must_contain": [".env", ".htpasswd", ".htaccess"],
        "must_not_contain": ["apidoc", "docs"],
        "min_status": 200,
        "max_status": 403
    }
}

LOG_FILE = "misclassified_tags.txt"

def log_misclassification(url, tag, reason):
    with open(LOG_FILE, "a") as f:
        f.write(f"[MISCLASSIFIED] Tag: {tag} | URL: {url} | Reason: {reason}\n")

def validate_tagged_entry(entry):
    tag    = entry.get("ai_tag", "Unknown")
    url    = entry.get("url", "").lower()
    status = entry.get("status", 0)

    rules = TAG_RULES.get(tag)
    if not rules:
        return True  # no specific rule → accept by default

    # Check required substrings
    if rules.get("must_contain") and not any(kw in url for kw in rules["must_contain"]):
        log_misclassification(url, tag, "Missing required keyword")
        return False

    # Check forbidden substrings
    if rules.get("must_not_contain") and any(bad_kw in url for bad_kw in rules["must_not_contain"]):
        log_misclassification(url, tag, "Contains forbidden keyword")
        return False

    # Check status range
    if status < rules.get("min_status", 100) or status > rules.get("max_status", 599):
        log_misclassification(url, tag, f"Status {status} out of allowed range")
        return False

    return True

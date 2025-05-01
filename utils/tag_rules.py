# 📁 File: dirhunter_ai/utils/tag_rules.py

tags = {
    "Admin Panel": {
        "exclude_keywords": ["/api", "/docs", "/apidocs", ".json", ".js"],
        "must_have_keywords": ["/admin", "/manage", "/panel"]
    },
    "Database": {
        "exclude_keywords": ["db.js", "db.json", "apidoc"],
        "must_have_keywords": ["/phpmyadmin", "/sqladmin", "/database"]
    },
    "Backup": {
        "exclude_keywords": ["/backup.js", "/backup.json"],
        "must_have_keywords": [".bak", ".tar", ".zip", ".gz"]
    },
    "Credentials/Secrets": {
        "exclude_keywords": ["/docs", "/apidoc"],
        "must_have_keywords": [".env", ".htpasswd", ".htaccess"]
    },
    # Add more tag-specific rules here
}

def is_tag_valid(tag, url, content_length, status):
    url = url.lower()
    
    rules = tags.get(tag)
    if not rules:
        return True  # no specific rules → allow

    # Exclude if blacklisted keyword present
    for bad_kw in rules.get("exclude_keywords", []):
        if bad_kw in url:
            return False

    # Require at least one good keyword
    if rules.get("must_have_keywords"):
        if not any(good_kw in url for good_kw in rules["must_have_keywords"]):
            return False

    # Example length check (optional, can expand)
    if content_length < 100:
        return False

    return True

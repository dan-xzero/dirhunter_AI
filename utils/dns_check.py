# utils/dns_check.py
"""DNS validation utility to check domain availability before scanning"""

import socket
import logging
import requests
from urllib.parse import urlparse
from typing import List, Tuple

logger = logging.getLogger(__name__)

def extract_hostname(url: str) -> str:
    """Extract hostname from URL or domain string"""
    # If it starts with http:// or https://, parse it as a URL
    if url.startswith(('http://', 'https://')):
        parsed = urlparse(url)
        return parsed.hostname or parsed.netloc or url
    
    # If it doesn't start with protocol but contains a path, extract just the hostname
    if '/' in url:
        return url.split('/')[0]
    
    # Otherwise, return the domain as is
    return url

def check_dns(domain: str) -> bool:
    """Check if domain resolves via DNS"""
    hostname = extract_hostname(domain)
    
    try:
        # Try to resolve the domain
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {hostname}: {e}")
        # Initial DNS check failed, try with http/https
        return check_with_http_https(domain)
    except Exception as e:
        logger.error(f"Unexpected error checking DNS for {hostname}: {e}")
        return check_with_http_https(domain)

def check_with_http_https(domain: str) -> bool:
    """Try to connect to the domain with http:// and https:// prefixes"""
    # Don't add prefix if it already has one
    if domain.startswith(('http://', 'https://')):
        urls_to_try = [domain]
    else:
        urls_to_try = [f"http://{domain}", f"https://{domain}"]
    
    for url in urls_to_try:
        try:
            logger.info(f"Trying to connect to {url}")
            from utils.user_agent_manager import get_realistic_headers
            headers = get_realistic_headers(include_scanner_header=True)
            response = requests.head(url, headers=headers, timeout=10, allow_redirects=True)
            if response.status_code < 400:
                logger.info(f"Successfully connected to {url} (Status: {response.status_code})")
                return True
        except requests.RequestException as e:
            logger.warning(f"Failed to connect to {url}: {e}")
    
    return False

def validate_domains(domains: List[str]) -> Tuple[List[str], List[str]]:
    """
    Validate a list of domains for DNS resolution
    Returns: (valid_domains, invalid_domains)
    """
    valid = []
    invalid = []
    
    for domain in domains:
        if check_dns(domain):
            valid.append(domain)
            logger.info(f"✓ DNS OK: {domain}")
        else:
            invalid.append(domain)
            logger.warning(f"✗ DNS/HTTP FAIL: {domain}")
    
    return valid, invalid

def pre_scan_dns_check(domains: List[str]) -> List[str]:
    """
    Pre-scan DNS check with user notification
    Returns only valid domains
    """
    print(f"\n[*] Performing DNS and connectivity validation for {len(domains)} domain(s)...")
    
    valid, invalid = validate_domains(domains)
    
    if invalid:
        print(f"\n[!] DNS/HTTP resolution failed for {len(invalid)} domain(s):")
        for domain in invalid:
            print(f"    - {domain}")
        print("\nThese domains will be skipped.\n")
    
    if not valid:
        print("[!] No valid domains found. Exiting.")
        return []
    
    print(f"\n[+] {len(valid)} domain(s) passed validation")
    return valid 
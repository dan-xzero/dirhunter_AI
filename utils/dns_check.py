# utils/dns_check.py
"""DNS validation utility to check domain availability before scanning"""

import socket
import logging
from urllib.parse import urlparse
from typing import List, Tuple

logger = logging.getLogger(__name__)

def extract_hostname(url: str) -> str:
    """Extract hostname from URL or domain string"""
    if not url.startswith(('http://', 'https://')):
        return url
    
    parsed = urlparse(url)
    return parsed.hostname or parsed.netloc or url

def check_dns(domain: str) -> bool:
    """Check if domain resolves via DNS"""
    hostname = extract_hostname(domain)
    
    try:
        # Try to resolve the domain
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {hostname}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error checking DNS for {hostname}: {e}")
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
            logger.warning(f"✗ DNS FAIL: {domain}")
    
    return valid, invalid

def pre_scan_dns_check(domains: List[str]) -> List[str]:
    """
    Pre-scan DNS check with user notification
    Returns only valid domains
    """
    print(f"\n[*] Performing DNS validation for {len(domains)} domain(s)...")
    
    valid, invalid = validate_domains(domains)
    
    if invalid:
        print(f"\n[!] DNS resolution failed for {len(invalid)} domain(s):")
        for domain in invalid:
            print(f"    - {domain}")
        print("\nThese domains will be skipped.\n")
    
    if not valid:
        print("[!] No valid domains found. Exiting.")
        return []
    
    print(f"\n[+] {len(valid)} domain(s) passed DNS validation")
    return valid 
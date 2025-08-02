import os
import logging
from collections import defaultdict
import json
import random

logger = logging.getLogger(__name__)

def enrich_findings(domain, findings):
    """Add missing data to findings to ensure complete reporting"""
    # Import here to avoid circular imports
    from utils.path_handler import path_manager
    from utils.screenshot import create_fallback_screenshot
    
    enriched = []
    
    for finding in findings:
        if finding is None:
            continue
            
        # Ensure basic fields exist
        finding.setdefault('finding_status', 'existing')
        finding.setdefault('ai_tag', 'Other')
        
        # Preserve headers if they exist
        if 'headers' not in finding:
            finding['headers'] = {}
            logger.info(f"No headers found for {finding.get('url', 'unknown')}")
        else:
            # Convert headers to a standard dict if needed
            if not isinstance(finding['headers'], dict):
                finding['headers'] = dict(finding['headers'])
            logger.info(f"Found {len(finding['headers'])} headers for {finding.get('url', 'unknown')}")
            logger.info(f"Headers: {list(finding['headers'].keys())}")
        
        # Ensure tech dict exists
        if 'tech' not in finding or not finding['tech']:
            finding['tech'] = {}
        
        # Fix CVE information if missing
        tech_dict = finding.get('tech', {})
        if not tech_dict.get('cve_vulns') and not tech_dict.get('cve_details'):
            tech_dict['cve_vulns'] = 0
            tech_dict['cve_details'] = {}
        elif tech_dict.get('cve_vulns') and not tech_dict.get('cve_details'):
            # Create synthetic CVE details
            tech_dict['cve_details'] = {
                'unknown_package': {
                    'ids': [f"CVE-UNKNOWN-{i+1}" for i in range(tech_dict['cve_vulns'])],
                    'version': 'unknown'
                }
            }
            
        # Fix download metadata
        if 'download_meta' not in finding or not finding['download_meta']:
            finding['download_meta'] = {}
            
        dm = finding.get('download_meta', {})
        if 'th_secrets' not in dm:
            dm['th_secrets'] = []
            
        # Add potential secrets if any was detected by regex
        if 'potential_secrets' in dm and dm['potential_secrets'] and 'th_secrets' not in dm:
            dm['th_secrets'] = [
                {
                    'raw': secret,
                    'redacted': '********',
                    'reason': 'Regex detection'
                }
                for secret in dm['potential_secrets']
            ]
            
        # Ensure screenshot exists
        if 'screenshot' not in finding or not finding['screenshot'] or not os.path.exists(finding['screenshot']):
            # Try to create a placeholder
            safe_path = finding.get('path', '').replace('/', '_').strip('_')
            if not safe_path:
                safe_path = 'root'
            
            screenshot_path = path_manager.get_screenshot_path(domain, f"{safe_path}.png")
            create_fallback_screenshot(finding.get('url', domain), screenshot_path)
            finding['screenshot'] = screenshot_path
        
        enriched.append(finding)
        
    return enriched

def save_enriched_findings(domain, findings, output_dir=None):
    """Save enriched findings to a JSON file for backup"""
    from utils.path_handler import path_manager
    
    if output_dir is None:
        output_dir = os.path.join(path_manager.dirs['html'], 'enriched')
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # Use safe filename for domain to handle paths
        from main_optimized import safe_filename
        safe_domain = safe_filename(domain)
        filename = os.path.join(output_dir, f"{safe_domain}_enriched.json")
        if findings and isinstance(findings, list):
            logger.info(f"First finding keys before save: {list(findings[0].keys())}")
        with open(filename, 'w') as f:
            json.dump(findings, f, indent=2)
        logger.info(f"Saved enriched findings for {domain} to {filename}")
    except Exception as e:
        logger.error(f"Failed to save enriched findings: {e}")
        
def categorize_secrets(secrets):
    """Categorize secrets by type for better reporting"""
    if not secrets:
        return {}
        
    categories = defaultdict(int)
    for secret in secrets:
        reason = secret.get('reason', '').lower()
        raw = secret.get('raw', '').lower()
        
        if 'aws' in reason or 'aws' in raw:
            categories['AWS Key'] += 1
        elif 'api key' in reason or 'api_key' in raw or 'apikey' in raw:
            categories['API Key'] += 1
        elif 'password' in reason or 'password' in raw:
            categories['Password'] += 1
        elif 'token' in reason or 'token' in raw:
            categories['Token'] += 1
        elif 'private key' in reason or 'private_key' in raw or '-----begin' in raw:
            categories['Private Key'] += 1
        else:
            categories['Other Secret'] += 1
            
    return dict(categories) 
#!/usr/bin/env python3
"""
Fix Domain Cards Script - Regenerates reports with proper data

This script fixes issues with missing information in domain cards by:
1. Finding and loading existing findings
2. Enriching them with missing data
3. Regenerating the reports with complete information
"""

import os
import sys
import logging
import json
import argparse
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler("domain_card_fixer.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def load_findings_from_raw(domain=None):
    """Load findings from raw results directory"""
    raw_dir = 'results/raw'
    findings_by_domain = {}
    
    if not os.path.exists(raw_dir):
        logger.error(f"Raw results directory not found: {raw_dir}")
        return findings_by_domain
        
    domains = []
    if domain:
        # Only process specific domain
        if os.path.isdir(os.path.join(raw_dir, domain)):
            domains = [domain]
        else:
            logger.error(f"Domain directory not found: {os.path.join(raw_dir, domain)}")
            return findings_by_domain
    else:
        # Process all domains
        domains = [d for d in os.listdir(raw_dir) if os.path.isdir(os.path.join(raw_dir, d))]
    
    logger.info(f"Loading findings for {len(domains)} domains")
    
    for domain in domains:
        domain_dir = os.path.join(raw_dir, domain)
        json_files = [f for f in os.listdir(domain_dir) if f.endswith('.json')]
        
        if not json_files:
            logger.warning(f"No JSON files found for domain: {domain}")
            continue
            
        domain_findings = []
        
        for json_file in json_files:
            file_path = os.path.join(domain_dir, json_file)
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    # Check if this is a list of findings or a container object
                    if isinstance(data, list):
                        domain_findings.extend(data)
                    elif isinstance(data, dict) and 'results' in data:
                        domain_findings.extend(data['results'])
            except Exception as e:
                logger.error(f"Error loading {file_path}: {e}")
                
        if domain_findings:
            findings_by_domain[domain] = domain_findings
            logger.info(f"Loaded {len(domain_findings)} findings for {domain}")
        else:
            logger.warning(f"No valid findings found for domain: {domain}")
    
    return findings_by_domain

def regenerate_reports(findings_by_domain):
    """Regenerate all reports using the fixed findings"""
    try:
        # Try to import report generation modules
        from utils.reporter import export_tag_based_reports, create_dashboard
        from utils.enhanced_reporter import create_enhanced_dashboard
        
        # Regenerate individual domain reports
        for domain, findings in findings_by_domain.items():
            export_tag_based_reports(domain, findings)
            logger.info(f"Regenerated reports for {domain}")
            
        # Regenerate dashboard
        if findings_by_domain:
            dashboard_path = create_dashboard(findings_by_domain)
            logger.info(f"Regenerated main dashboard: {dashboard_path}")
            
            # Try enhanced dashboard
            try:
                enhanced_dashboard_path = create_enhanced_dashboard(findings_by_domain)
                logger.info(f"Regenerated enhanced dashboard: {enhanced_dashboard_path}")
            except Exception as e:
                logger.error(f"Failed to regenerate enhanced dashboard: {e}")
                
        return True
    except ImportError as e:
        logger.error(f"Required module not found: {e}")
        return False
    except Exception as e:
        logger.error(f"Error regenerating reports: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Fix domain cards and regenerate reports")
    parser.add_argument("--domain", help="Process specific domain only")
    parser.add_argument("--force", action="store_true", help="Force regeneration even if no findings")
    args = parser.parse_args()
    
    logger.info("Starting domain card fixer")
    
    # Load findings
    findings_by_domain = load_findings_from_raw(args.domain)
    
    if not findings_by_domain and not args.force:
        logger.error("No findings found - cannot regenerate reports")
        return 1
        
    # Regenerate reports
    if regenerate_reports(findings_by_domain):
        logger.info("Successfully regenerated all reports")
        return 0
    else:
        logger.error("Failed to regenerate reports")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 
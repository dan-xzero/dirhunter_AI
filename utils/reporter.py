# File: dirhunter_ai/utils/reporter.py

import os
import time
import re
import hashlib
import json
import logging
from datetime import datetime
from collections import defaultdict
import requests
from functools import lru_cache

import re
from collections import Counter

# Set up logger
logger = logging.getLogger(__name__)

HTML_REPORT_DIR = "results/html"



def _slugify_name(value: str) -> str:
    """Return a filesystem- and URL-safe slug for arbitrary strings (domains, tags, etc.)."""
    # Remove URL scheme for domains
    value = re.sub(r"^[a-zA-Z]+://", "", value)
    # Replace non-alphanum (except dot, dash, underscore) with underscore
    value = re.sub(r"[^0-9A-Za-z._-]+", "_", value)
    # Collapse consecutive underscores
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "item"





def slugify_tag(tag):
    """Convert a tag to a URL-friendly slug"""
    return tag.lower().replace(' ', '_').replace('-', '_')

def _render_tech_list(tech_items, tech_versions):
    html = ""
    for tech_name, count in tech_items.most_common(10):
        version = tech_versions.get(tech_name, "")
        html += f'<div class="tech-item">{tech_name}'
        if version:
            html += f'span class="tech-version">{version}</span>'
        html += '</div>'
    return html

def create_dashboard(results, output_path=None, is_update=False):
    """Create HTML dashboard from results"""
    if not output_path:
        output_path = os.path.join("results", "html", "dashboard.html")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # If results is empty, try to load from enriched JSON files
    if not results:
        results = {}
        enriched_dir = os.path.join("results", "html", "enriched")
        if os.path.exists(enriched_dir):
            for filename in os.listdir(enriched_dir):
                if filename.endswith("_enriched.json"):
                    domain = filename.replace("_enriched.json", "")
                    try:
                        with open(os.path.join(enriched_dir, filename), 'r') as f:
                            findings = json.load(f)
                            if findings:
                                results[domain] = findings
                    except Exception as e:
                        print(f"Error loading {filename}: {e}")
    
    # Start with the HTML template
    with open(output_path, "w") as f_handle:
        f_handle.write("""<!DOCTYPE html>
<html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding-top: 0;
            background-color: #f5f5f7;
            margin: 0;
        }
        .card {
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border: none;
            border-radius: 10px;
        }
        .domain-card {
                transition: transform 0.2s;
            border-top: 4px solid #007bff;
            background-color: white;
        }
        .domain-card:hover {
            transform: translateY(-5px);
        }
        .status-new {
            color: #28a745;
            font-weight: bold;
        }
        .status-changed {
            color: #17a2b8;
            font-weight: bold;
        }
        .status-existing {
            color: #6c757d;
            font-weight: bold;
        }
        .tech-stats-container {
                display: flex;
            gap: 10px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }
        .tech-stat-card {
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 5px;
            flex: 1;
            min-width: 120px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                text-align: center;
        }
        .tech-stat-value {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 5px;
            color: #333;
        }
        .tech-stat-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .tech-categories-grid {
                display: flex;
                flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 15px;
        }
        .tech-category-item {
            padding: 6px 12px;
            border-radius: 15px;
            background-color: #e9ecef;
            font-size: 13px;
            display: inline-flex;
            align-items: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            transition: all 0.2s ease;
        }
        .tech-category-item:hover {
            background-color: #dee2e6;
            transform: translateY(-2px);
            box-shadow: 0 2px 5px rgba(0,0,0,0.15);
        }
        .tech-category-item i {
            margin-right: 5px;
        }
        .tech-details {
            background-color: #f8f9fa;
            padding: 12px;
            border-radius: 5px;
            margin-top: 10px;
            display: none;
            border: 1px solid #dee2e6;
        }
        .tech-item {
            padding: 6px 10px;
            margin-bottom: 6px;
            border-radius: 4px;
            background-color: white;
            font-size: 14px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
                display: flex;
                justify-content: space-between;
            align-items: center;
        }
        .tech-item:hover {
            background-color: #f1f3f5;
        }
        .tech-version {
            padding: 2px 8px;
            border-radius: 10px;
            background-color: #e9ecef;
            font-size: 12px;
                font-weight: 500;
            letter-spacing: 0.5px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }
        .filter-bar {
            position: sticky;
            top: 0;
            background-color: white;
            padding: 15px;
            z-index: 100;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            margin-bottom: 20px;
        }
        .toggle-button {
            cursor: pointer;
            user-select: none;
            color: #007bff;
            margin-top: 10px;
            display: inline-block;
        }
        .toggle-button i {
            transition: transform 0.3s ease;
        }
        .toggle-button.active i {
            transform: rotate(90deg);
        }
        .security-posture {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            border: 1px solid #dee2e6;
        }
        .security-summary {
            margin-bottom: 15px;
            line-height: 1.5;
        }
        .recommendations-list {
            margin-bottom: 15px;
            padding-left: 20px;
        }
        .recommendations-list li {
            margin-bottom: 8px;
        }
        .missing-headers-list {
            background-color: #fff3cd;
            padding: 10px;
            border-radius: 4px;
            border-left: 4px solid #ffc107;
        }
        .cve-header {
            cursor: pointer;
            padding: 8px;
            background-color: #f1f3f5;
            border-radius: 4px;
            margin-bottom: 5px;
        }
        .cve-header:hover {
            background-color: #e9ecef;
        }
        .cve-details {
            margin-top: 8px;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            overflow: hidden;
        }
        /* Doughnut chart for CVE severity */
        .cve-chart-container {
            position: relative;
                width: 100%;
            max-width: 300px;
            margin: 0 auto;
        }
        .severity-legend {
                display: flex;
                flex-wrap: wrap;
            gap: 10px;
            justify-content: center;
            margin-top: 10px;
        }
        .severity-legend-item {
                display: flex;
                align-items: center;
            font-size: 12px;
        }
        .severity-legend-color {
            width: 12px;
            height: 12px;
            margin-right: 5px;
            border-radius: 2px;
        }
        .main-header {
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            color: white;
            padding: 40px 0;
            margin-bottom: 30px;
            text-align: center;
        }
        .main-title {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        .btn-primary {
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            border: none;
        }
        .vulnerability-summary {
            background-color: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .vulnerability-summary h3 {
            margin-bottom: 20px;
            font-weight: 600;
        }
        .vulnerability-stat {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 8px;
            text-align: center;
        }
        .vulnerability-count {
            font-size: 1.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .vulnerability-label {
            font-size: 0.9rem;
            text-transform: uppercase;
            color: #6c757d;
        }
        .critical-count {
            color: #dc3545;
        }
        .high-count {
            color: #fd7e14;
        }
        .medium-count {
            color: #0dcaf0;
        }
        .low-count {
            color: #6c757d;
        }
        .domain-title {
            font-size: 1.5rem;
            margin-bottom: 5px;
        }
        .domain-title a {
            color: inherit;
            text-decoration: none;
        }
        .domain-title a:hover {
            color: #6366f1;
        }
        .endpoints-count {
            color: #6c757d;
            margin-bottom: 15px;
        }
        .status-indicator {
            display: flex;
            margin-bottom: 15px;
        }
        .status-count {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-right: 15px;
        }
        .status-count-value {
            font-weight: bold;
            font-size: 1.2rem;
        }
        .view-technologies-button {
            display: flex;
            align-items: center;
            color: #6366f1;
            cursor: pointer;
            margin-top: 10px;
        }
        .view-technologies-button i {
            margin-right: 5px;
            transition: transform 0.2s;
        }
        .view-tech-btn {
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }
        .tech-chevron {
            transition: transform 0.3s;
        }
        .domain-action-buttons {
            display: flex;
        }
        .top-tags a {
            display: inline-block;
            margin-right: 8px;
            margin-bottom: 8px;
            padding: 6px 12px;
            background-color: #f8f9fa;
            border-radius: 20px;
            color: #333;
            text-decoration: none;
            font-size: 0.9rem;
        }
        .top-tags a:hover {
            background-color: #e9ecef;
        }
        .filter-container {
            background-color: #fff;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            position: sticky;
            top: 15px;
            z-index: 1000;
        }
        .filter-row {
            display: flex;
            gap: 15px;
        }
        .filter-item {
            flex: 1;
        }
        .top-tags-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }
        .tag-badge {
            display: inline-flex;
            align-items: center;
            background-color: #f0f4f8;
            border-radius: 20px;
            overflow: hidden;
            text-decoration: none;
            transition: all 0.2s;
            border: 1px solid #e2e8f0;
        }
        .tag-badge:hover {
            transform: translateY(-2px);
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            background-color: #e5edfa;
            text-decoration: none;
        }
        .tag-name {
            padding: 6px 12px;
            color: #3f51b5;
            font-size: 0.85rem;
        }
        .tag-count {
            background-color: #3f51b5;
            color: white;
            padding: 6px 8px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        .status-link {
            text-decoration: none;
            color: inherit;
            display: block;
            transition: all 0.2s ease;
        }
        .status-link:hover {
            text-decoration: none;
            color: inherit;
            transform: translateY(-2px);
        }
        .quick-filters {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #e9ecef;
        }
        .quick-filters .form-select {
            font-size: 0.85rem;
        }
        .quick-filters .btn {
            font-size: 0.85rem;
            transition: all 0.2s ease;
        }
        .quick-filters .btn:hover {
            transform: translateY(-1px);
        }
        .quick-filters .collapse {
            border-radius: 8px;
        }
        .quick-filters .card-body {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
        }
        .quick-filters .card-body a {
            color: #495057;
            font-size: 0.8rem;
        }
        .quick-filters .card-body a:hover {
            color: #007bff;
        }
        .quick-filters .fas.fa-chevron-down {
            transition: transform 0.2s ease;
        }
        .quick-filters .btn[aria-expanded="true"] .fas.fa-chevron-down {
            transform: rotate(180deg);
        }
        
        /* Scan Overview Section Styles */
        .scan-overview-section {
            margin-bottom: 2rem;
        }
        .scan-overview-section .card {
            border: none;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .scan-overview-section .card-header {
            border-bottom: none;
            padding: 1.5rem;
        }
        .scan-overview-section .card-header h3 {
            font-size: 1.5rem;
            font-weight: 600;
        }
        .scan-overview-section .card-body {
            padding: 1.5rem;
        }
        .new-findings-overview h5 {
            font-weight: 600;
            border-bottom: 2px solid #28a745;
            padding-bottom: 0.5rem;
        }
        .new-findings-overview .btn-link {
            font-size: 1.1rem;
            font-weight: 600;
        }
        .new-findings-overview .btn-link:hover {
            text-decoration: none !important;
        }
        .new-findings-overview .btn-link i {
            transition: transform 0.3s ease;
        }
        .new-findings-overview .btn-link[aria-expanded="true"] i {
            transform: rotate(180deg);
        }
        .new-findings-overview .collapse {
            transition: all 0.3s ease;
        }
        .new-findings-grid {
            display: grid;
            gap: 1.5rem;
        }
        .domain-new-findings {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 1rem;
            border-left: 4px solid #28a745;
        }
        .domain-name {
            font-weight: 600;
            margin-bottom: 1rem;
        }
        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        .finding-item {
            background-color: white;
            border-radius: 6px;
            padding: 0.75rem;
            border: 1px solid #e9ecef;
            transition: all 0.2s ease;
        }
        .finding-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            border-color: #007bff;
        }
        .finding-link {
            color: #495057;
            text-decoration: none;
            display: flex;
            align-items: center;
            font-size: 0.9rem;
            font-weight: 500;
        }
        .finding-link:hover {
            color: #007bff;
            text-decoration: none;
        }
        .finding-link i {
            color: #6c757d;
            font-size: 0.8rem;
        }
        
        /* Overview Statistics Styles */
        .overview-stats {
            background-color: #f8f9fa;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            padding: 1.5rem;
            border-radius: 8px;
            background-color: white;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s ease;
        }
        .stat-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .stat-number {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        .stat-label {
            font-size: 0.9rem;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 500;
        }
        .new-stat .stat-number {
            color: #28a745;
        }
        
        /* No Changes Message Styles */
        .no-changes-message {
            padding: 2rem;
        }
        .no-changes-message i {
            margin-bottom: 1rem;
        }
        .no-changes-message h5 {
            margin-bottom: 1rem;
            font-weight: 600;
        }
        .no-changes-message p {
            font-size: 1.1rem;
            line-height: 1.6;
        }
        </style>
    </head>
    <body>
    <header class="main-header">
        <h1>🛡️ DirHunter AI Security Dashboard</h1>
        <p>Comprehensive view of security findings and technology stack</p>
    </header>
    
    <div class="container">
        <!-- Filter Bar -->
        <div class="filter-container sticky-top">
            <div class="filter-row">
                <div class="filter-item">
                    <input type="text" class="form-control" id="domain-filter" placeholder="Filter by domain...">
            </div>
                <div class="filter-item">
                    <select class="form-select" id="status-filter">
                        <option value="all">All Statuses</option>
                        <option value="new">New</option>
                        <option value="changed">Changed</option>
                        <option value="existing">Existing</option>
                    </select>
                </div>
                <div class="filter-item">
                    <select class="form-select" id="tag-filter">
                        <option value="all">All Tags</option>
                    </select>
                </div>

                <div class="filter-item">
                    <button class="btn btn-primary w-100" id="reset-filters">Reset Filters</button>
                </div>
                </div>
            </div>
            
        <div id="domains-container">
""")

        # Process domains and add domain cards
        all_tags = set()
        all_techs = set()
        all_domain_techs = {}
        
        # Collect all new findings across all domains for overview
        all_new_findings = []
        all_changed_findings = []
        all_existing_findings = []
        
                # First pass: collect all findings by status
        for domain, findings in results.items():
            if not findings:
                continue
            for finding in findings:
                status = finding.get('finding_status', 'existing')
                if status == 'new':
                    all_new_findings.append({'domain': domain, 'finding': finding})
                elif status == 'changed':
                    all_changed_findings.append({'domain': domain, 'finding': finding})
                elif status == 'existing':
                    all_existing_findings.append({'domain': domain, 'finding': finding})
        
        # Add Scan Overview Section
        if all_new_findings:
            f_handle.write(f"""
            <!-- Scan Overview Section -->
            <div class="scan-overview-section mb-4">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h3 class="mb-0"><i class="fas fa-chart-line me-2"></i>Scan Overview - New Findings</h3>
                    </div>
                    <div class="card-body">
                        <!-- Overview Statistics -->
                        <div class="overview-stats mb-4">
                            <div class="row text-center">
                                <div class="col-md-12">
                                    <div class="stat-card new-stat">
                                        <div class="stat-number">{len(all_new_findings)}</div>
                                        <div class="stat-label">New Findings</div>
                                    </div>
                                </div>
                            </div>
                        </div>
            """)
            
            # Show new findings overview
            if all_new_findings:
                f_handle.write(f"""
                        <div class="new-findings-overview mb-4">
                            <h5 class="text-success mb-3">
                                <button class="btn btn-link text-success p-0 text-decoration-none" type="button" data-bs-toggle="collapse" data-bs-target="#newFindingsCollapse" aria-expanded="false" aria-controls="newFindingsCollapse">
                                    <i class="fas fa-chevron-down me-2"></i>New Findings ({len(all_new_findings)})
                                </button>
                            </h5>
                            <div class="collapse" id="newFindingsCollapse">
                                <div class="new-findings-grid">
                """)
                
                # Group new findings by domain
                new_by_domain = {}
                for item in all_new_findings:
                    domain = item['domain']
                    if domain not in new_by_domain:
                        new_by_domain[domain] = []
                    new_by_domain[domain].append(item['finding'])
                
                for domain, findings in new_by_domain.items():
                    f_handle.write(f"""
                                <div class="domain-new-findings mb-3">
                                    <h6 class="domain-name text-primary mb-2">
                                        <i class="fas fa-globe me-2"></i>{domain}
                                    </h6>
                                    <div class="findings-list">
                    """)
                    
                    for finding in findings:
                        url = finding.get('url', '')
                        path = finding.get('path', '/')
                        if not path or path == 'unknown':
                            path = '/'
                        f_handle.write(f"""
                                        <div class="finding-item">
                                            <a href="{url}" target="_blank" class="finding-link">
                                                <i class="fas fa-external-link-alt me-2"></i>{path}
                                            </a>
                                        </div>
                        """)
                    
                    f_handle.write("""
                                    </div>
                                </div>
                    """)
                
                f_handle.write("""
                                </div>
                            </div>
                        </div>
                """)
            

            
            f_handle.write("""
                    </div>
                </div>
            </div>
            """)
        else:
            # No new or changed findings
            f_handle.write("""
            <!-- Scan Overview Section -->
            <div class="scan-overview-section mb-4">
                <div class="card">
                    <div class="card-header bg-success text-white">
                        <h3 class="mb-0"><i class="fas fa-check-circle me-2"></i>Scan Overview - No Changes Detected</h3>
                    </div>
                    <div class="card-body text-center">
                        <div class="no-changes-message">
                            <i class="fas fa-shield-check fa-3x text-success mb-3"></i>
                            <h5 class="text-success">Great News!</h5>
                            <p class="text-muted">No new findings or changes were detected in this scan. All domains appear to be secure.</p>
                        </div>
                    </div>
                </div>
            </div>
            """)
        
        # Get current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # For each domain
        for domain, findings in results.items():
            if not findings:
                continue
            
            # Create findings page for the domain
            export_domain_findings(domain, findings, os.path.dirname(output_path))
            export_tag_based_reports(domain, findings, os.path.dirname(output_path))
            
            # Get safe filename for links
            from main_optimized import safe_filename
            safe_domain = safe_filename(domain)
            
            # Count by status
            new_count = sum(1 for f in findings if f.get('finding_status') == 'new')
            changed_count = sum(1 for f in findings if f.get('finding_status') == 'changed')
            existing_count = sum(1 for f in findings if f.get('finding_status') == 'existing')
            
            # Count by tag and collect all tags
            tags = {}
            for f in findings:
                tag = f.get('ai_tag', 'Other')
                if tag not in tags:
                    tags[tag] = 0
                tags[tag] += 1
                all_tags.add(tag)
            
            # Get technologies for this domain
            domain_techs = Counter()
            tech_details = {}  # Store tech name with version
            techs_with_version = 0
            tech_categories = Counter()
            
            for f in findings:
                # Basic finding processing (no tech/CVE analysis)
                pass
            
            # Store basic domain info for later use
            all_domain_techs[domain] = {
                "findings_count": len(findings)
            }
            
            # Write domain card
            f_handle.write(f"""
            <div class="card domain-card mb-4 domain-item">
                    <div class="card-body">
                    <h3 class="domain-title"><a href="{safe_domain}_findings.html">{domain}</a></h3>
                    <div class="endpoints-count">{len(findings)} endpoints</div>
                    
                    <div class="status-indicator">
                        <div class="status-count">
                            <a href="{safe_domain}_findings.html?status=new" class="status-link">
                            <span class="status-count-value status-new">{new_count}</span>
                            <small>New</small>
                            </a>
                            </div>
                        <div class="status-count">
                            <a href="{safe_domain}_findings.html?status=changed" class="status-link">
                            <span class="status-count-value status-changed">{changed_count}</span>
                            <small>Changed</small>
                            </a>
                            </div>
                        <div class="status-count">
                            <a href="{safe_domain}_findings.html?status=existing" class="status-link">
                            <span class="status-count-value status-existing">{existing_count}</span>
                            <small>Existing</small>
                            </a>
                            </div>
                        </div>
                        
                    <!-- Quick Filter Dropdowns -->
                    <div class="quick-filters mt-3">
                        <div class="row">
                            <div class="col-md-4">
                                <button class="btn btn-outline-success btn-sm w-100" type="button" data-bs-toggle="collapse" data-bs-target="#new-urls-{safe_domain}" aria-expanded="false">
                                    <i class="fas fa-chevron-down me-2"></i>New URLs ({new_count})
                                </button>
                                <div class="collapse mt-2" id="new-urls-{safe_domain}">
                                    <div class="card card-body p-2" style="max-height: 200px; overflow-y: auto;">
                                        {(''.join([f'<div class="mb-1"><small><a href="{f.get("url", "#")}" target="_blank" class="text-decoration-none">{f.get("url", "N/A")}</a></small></div>' for f in findings if f.get("finding_status") == "new"]))}
                        </div>
                    </div>
                </div>
                            <div class="col-md-4">
                                <button class="btn btn-outline-warning btn-sm w-100" type="button" data-bs-toggle="collapse" data-bs-target="#changed-urls-{safe_domain}" aria-expanded="false">
                                    <i class="fas fa-chevron-down me-2"></i>Changed URLs ({changed_count})
                                </button>
                                <div class="collapse mt-2" id="changed-urls-{safe_domain}">
                                    <div class="card card-body p-2" style="max-height: 200px; overflow-y: auto;">
                                        {(''.join([f'<div class="mb-1"><small><a href="{f.get("url", "#")}" target="_blank" class="text-decoration-none">{f.get("url", "N/A")}</a></small></div>' for f in findings if f.get("finding_status") == "changed"]))}
            </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <button class="btn btn-outline-secondary btn-sm w-100" type="button" data-bs-toggle="collapse" data-bs-target="#existing-urls-{safe_domain}" aria-expanded="false">
                                    <i class="fas fa-chevron-down me-2"></i>Existing URLs ({existing_count})
                </button>
                                <div class="collapse mt-2" id="existing-urls-{safe_domain}">
                                    <div class="card card-body p-2" style="max-height: 200px; overflow-y: auto;">
                                        {(''.join([f'<div class="mb-1"><small><a href="{f.get("url", "#")}" target="_blank" class="text-decoration-none">{f.get("url", "N/A")}</a></small></div>' for f in findings if f.get("finding_status") == "existing"]))}
                            </div>
                                </div>
                            </div>
                        </div>
                    </div>
                        

            """)
            


            
            # Add special counters for downloadables and secrets
            downloadable_count = sum(1 for f in findings if f.get('download_meta', {}).get('is_downloadable'))
            secret_count = sum(1 for f in findings if f.get('secrets'))
            
            f_handle.write('<h6 class="fw-bold mb-3">Security Findings</h6>')
            
            if downloadable_count > 0:
                f_handle.write(f'<div class="mb-2"><span class="badge bg-info text-dark"><i class="fas fa-download me-1"></i> {downloadable_count} Downloadable</span></div>')
            
            if secret_count > 0:
                f_handle.write(f'<div class="mb-2"><span class="badge bg-danger"><i class="fas fa-key me-1"></i> {secret_count} Secrets</span></div>')
            
            # Add buttons for findings and tag findings
            f_handle.write(f'''
            <div class="mt-4 mb-3 domain-action-buttons">
                <a href="{safe_domain}_findings.html" class="btn btn-sm btn-primary me-2">
                    <i class="fas fa-search"></i> View Findings
                </a>
                <a href="{safe_domain}_tags.html" class="btn btn-sm btn-secondary">
                    <i class="fas fa-tags"></i> View by Tags
                </a>
                            </div>
            ''')
            
            # Check for missing security headers
            all_headers = []
            for finding in findings:
                headers = finding.get('headers', {})
                for header_name in headers:
                    all_headers.append(header_name.lower())
            
            # Define important security headers
            security_headers = [
                {'name': 'Content-Security-Policy', 'importance': 'critical'},
                {'name': 'X-Frame-Options', 'importance': 'high'},
                {'name': 'X-Content-Type-Options', 'importance': 'medium'},
                {'name': 'Strict-Transport-Security', 'importance': 'critical'},
                {'name': 'X-XSS-Protection', 'importance': 'high'},
                {'name': 'Referrer-Policy', 'importance': 'medium'},
                {'name': 'Feature-Policy', 'importance': 'low'},
                {'name': 'Permissions-Policy', 'importance': 'low'},
                {'name': 'X-Permitted-Cross-Domain-Policies', 'importance': 'low'}
            ]
            
            missing_headers = [header for header in security_headers if header['name'].lower() not in [h.lower() for h in all_headers]]
            
            if missing_headers:
                f_handle.write("""
                <div class="mt-3">
                    <h6 class="fw-bold">Missing Security Headers</h6>
                    <div class="missing-headers-list">
                """)
                
                for header in missing_headers:
                    badge_class = {
                        'critical': 'danger',
                        'high': 'warning',
                        'medium': 'info',
                        'low': 'secondary'
                    }.get(header['importance'], 'secondary')
                    
                    f_handle.write(f'<div class="mb-1"><span class="badge bg-{badge_class}">{header["name"]}</span></div>')
                    
                f_handle.write('</div></div>')
            
            # Add tags
            if tags:
                f_handle.write("""
                <div class="mt-3">
                    <h6 class="fw-bold">Top Tags</h6>
                    <div class="top-tags-container">
                """)
                
                for tag, count in sorted(tags.items(), key=lambda x: x[1], reverse=True)[:5]:
                    tag_id = slugify_tag(tag)
                    f_handle.write(f'<a href="{safe_domain}_tag_{tag_id}.html" class="tag-badge"><span class="tag-name">{tag}</span><span class="tag-count">{count}</span></a>')
                    
                f_handle.write('</div></div>')
            

            
            f_handle.write("""
                </div>
            </div>
            """)
        


        
        f_handle.write('</div>') # Close domains-container
        
        # Close HTML and add JavaScript
        f_handle.write(f"""
            <div class="text-center text-muted mt-4 mb-4">
                <small>Generated at {timestamp}</small>
            </div>
        </div>
        
        <!-- Bootstrap JS -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
        
        <script>
            function toggleDetails(button, detailsId) {{
                const chevron = button.querySelector('.tech-chevron');
                if (chevron) {{
                    chevron.style.transform = chevron.style.transform === 'rotate(90deg)' ? 'rotate(0)' : 'rotate(90deg)';
                }}
                const details = document.getElementById(detailsId);
                details.style.display = details.style.display === 'block' ? 'none' : 'block';
            }}
            
            document.addEventListener('DOMContentLoaded', function() {{
            const domainFilter = document.getElementById('domain-filter');
            const statusFilter = document.getElementById('status-filter');
            const tagFilter = document.getElementById('tag-filter');

                const resetFilters = document.getElementById('reset-filters');
                const domainItems = document.querySelectorAll('.domain-item');
            
            // Populate tag filter dynamically from findings
                const allTags = new Set();
                domainItems.forEach(item => {{
                    const tagLinks = item.querySelectorAll('.top-tags-container a');
                    tagLinks.forEach(link => {{
                        const tagName = link.querySelector('.tag-name');
                        if (tagName) {{
                            allTags.add(tagName.textContent);
                        }}
                    }});
                }});
                
                allTags.forEach(tag => {{
                    const option = document.createElement('option');
                    option.value = tag;
                    option.textContent = tag;
                    tagFilter.appendChild(option);
                }});
            

                
                function applyFilters() {{
                const domainText = domainFilter.value.toLowerCase();
                const statusValue = statusFilter.value;
                const tagValue = tagFilter.value;

                    
                    domainItems.forEach(item => {{
                        const domainElement = item.querySelector('.domain-title a');
                        const domain = domainElement ? domainElement.textContent.toLowerCase() : '';
                        
                        // Basic domain text filter
                        const matchesDomain = domain.includes(domainText);
                        
                        // Skip other filters if domain doesn't match
                        if (!matchesDomain) {{
                            item.style.display = 'none';
                            return;
                        }}
                        
                        // Status filter
                    let matchesStatus = true;
                        if (statusValue !== 'all') {{
                            const statusElement = item.querySelector('.status-' + statusValue);
                            if (statusElement) {{
                                const statusCount = parseInt(statusElement.textContent);
                                matchesStatus = statusCount > 0;
                            }} else {{
                                matchesStatus = false;
                            }}
                        }}
                        
                        // Tag filter
                    let matchesTag = true;
                        if (tagValue !== 'all') {{
                            // Check if any tag badges contain the selected tag
                            const tagLinks = item.querySelectorAll('.top-tags-container a');
                            matchesTag = Array.from(tagLinks).some(link => 
                                link.textContent.toLowerCase().includes(tagValue.toLowerCase())
                            );
                        }}
                        
                        item.style.display = (matchesDomain && matchesStatus && matchesTag) ? 'block' : 'none';
                    }});
                }}
            
            domainFilter.addEventListener('input', applyFilters);
            statusFilter.addEventListener('change', applyFilters);
            tagFilter.addEventListener('change', applyFilters);

            
                resetFilters.addEventListener('click', function() {{
                domainFilter.value = '';
                statusFilter.value = 'all';
                tagFilter.value = 'all';

                    applyFilters();
                }});
                




            }});
        </script>
    </body>
</html>""")
    
    logger.info(f"Dashboard created: {output_path}")
    return output_path


def export_tag_based_reports(domain, findings, output_dir=HTML_REPORT_DIR):
    """
    Creates enhanced reports with better styling and finding status indicators
    """
    # Enrich findings to ensure all required data is present
    try:
        from utils.findings_enricher import enrich_findings, save_enriched_findings
        logger.info(f"Enriching {len(findings)} findings for {domain}")
        findings = enrich_findings(domain, findings)
        save_enriched_findings(domain, findings)
    except ImportError:
        logger.warning("findings_enricher not available - using raw findings")
    except Exception as e:
        logger.error(f"Error enriching findings: {e}")
        
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Group results by AI tag
    grouped = defaultdict(list)
    for f in findings:
        if f is None:
            continue
        tag = f.get("ai_tag", "Other")
        grouped[tag].append(f)

    dom_slug = _slugify_name(domain)
    # Build domain tag index
    tag_index_file = os.path.join(output_dir, f"{dom_slug}_tags.html")

    # Ensure parent directories exist for nested domain paths (e.g., "https://...")
    os.makedirs(os.path.dirname(tag_index_file), exist_ok=True)
    
    # Calculate finding status counts for this domain
    new_count = sum(1 for f in findings if f is not None and f.get('finding_status') == 'new')
    changed_count = sum(1 for f in findings if f is not None and f.get('finding_status') == 'changed')
    existing_count = sum(1 for f in findings if f is not None and f.get('finding_status') == 'existing')
    total_count = len([f for f in findings if f is not None])
    
    # Calculate secrets count
    secret_count = 0
    
    for f in findings:
        if f is None:
            continue
        
        # Count secrets
        dm = f.get('download_meta', {})
        if dm:
            secret_count += len(dm.get('th_secrets', [])) + len(dm.get('potential_secrets', []))

    # Calculate CVEs by severity
    cve_by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    all_cve_ids = []
    
    for f in findings:
        if f is None:
            continue
            
        # Extract CVEs and their details
        tech = f.get('tech', {})
        cve_details = tech.get('cve_details', {})
        
        if isinstance(cve_details, dict):
            # New format with package details
            for pkg, info in cve_details.items():
                if isinstance(info, dict) and 'ids' in info:
                    pass

    # Enhanced HTML with better styling
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{domain} - Security Findings</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f5f5f7;
                color: #1d1d1f;
            }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
                padding: 2rem;
        }}
        .header {{
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            color: white;
            padding: 2.5rem 0;
                margin-bottom: 2rem;
            }}
            .header h1 {{
                margin: 0;
            font-size: 2.5rem;
            font-weight: 700;
        }}
        .stats {{
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            margin-bottom: 2rem;
            padding: 1.5rem;
        }}
        .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1.5rem;
        }}
        .stat-item {{
                text-align: center;
            }}
        .stat-value {{
                font-size: 2rem;
            font-weight: 700;
        }}
        .new {{ color: #10b981; }}
        .changed {{ color: #3b82f6; }}
        .existing {{ color: #6b7280; }}
        .stat-label {{
            font-size: 0.875rem;
                color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .tags-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 1.5rem;
            margin-top: 1.5rem;
            }}
            .tag-card {{
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                overflow: hidden;
            transition: transform 0.3s, box-shadow 0.3s;
            display: flex;
                text-decoration: none;
            color: #1d1d1f;
            position: relative;
            }}
            .tag-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
            }}
            .tag-card .thumbnail {{
            width: 120px;
            height: 120px;
            background-color: #f5f5f7;
            flex-shrink: 0;
                object-fit: cover;
            }}
            .tag-card .content {{
            padding: 1rem;
            flex-grow: 1;
            }}
            .tag-card h3 {{
            margin: 0 0 0.5rem 0;
                font-size: 1.25rem;
            color: #1d1d1f;
            }}
            .tag-card .count {{
            font-size: 0.875rem;
                color: #6b7280;
            margin-bottom: 0.75rem;
            }}
            .tag-card .status-badges {{
                display: flex;
                flex-wrap: wrap;
                gap: 0.5rem;
            }}
            .badge {{
            display: inline-block;
                padding: 0.25rem 0.5rem;
            border-radius: 0.375rem;
            font-size: 0.75rem;
                font-weight: 500;
            line-height: 1;
            }}
            .badge.new {{
            background-color: #ecfdf5;
            color: #10b981;
            }}
            .badge.changed {{
            background-color: #eff6ff;
            color: #3b82f6;
            }}
            .badge.existing {{
            background-color: #f3f4f6;
            color: #6b7280;
            }}
        .chart-container {{
                background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                padding: 1.5rem;
                margin-bottom: 2rem;
        }}
        .action-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
                margin-bottom: 1.5rem;
        }}
        .back-link {{
            color: #6366f1;
            text-decoration: none;
            display: inline-flex;
                align-items: center;
            font-weight: 500;
        }}
        .back-link:hover {{
            text-decoration: underline;
        }}
        .back-link svg {{
            margin-right: 0.5rem;
            height: 1rem;
            width: 1rem;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="container">
                <h1>Findings by Tag: {domain}</h1>
                <p>Review security findings grouped by their detected purpose</p>
                </div>
        </div>
        
        <div class="container">
            <div class="action-bar">
                <a href="dashboard.html" class="back-link">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                    </svg>
                    Back to Dashboard
                </a>
            </div>
            
            <div class="stats">
                <h2>Findings Overview</h2>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-value">{total_count}</div>
                        <div class="stat-label">Total Findings</div>
                </div>
                    <div class="stat-item">
                        <div class="stat-value new">{new_count}</div>
                        <div class="stat-label">New</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value changed">{changed_count}</div>
                        <div class="stat-label">Changed</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value existing">{existing_count}</div>
                        <div class="stat-label">Existing</div>
                    </div>
                </div>
            </div>

            <div class="tags-grid">
    """

    # Sort tags for consistent display
    sorted_tags = sorted(grouped.items(), key=lambda x: (-len(x[1]), x[0]))

    for tag, items in sorted_tags:
        # Get status counts for this tag
        status_counts = defaultdict(int)
        for item in items:
            if item is None:
                continue
            status_counts[item.get('finding_status', 'unknown')] += 1
        
        # Pick representative screenshot
        rep_item = next((it for it in items if it is not None), None)
        if rep_item is None:
            continue

        screenshot_html = ""
        if rep_item.get("screenshot") and os.path.exists(rep_item["screenshot"]):
            screenshot_rel = os.path.relpath(rep_item["screenshot"], output_dir)
            screenshot_html = f'<img src="{screenshot_rel}" class="thumbnail" alt="{tag}">'
        else:
            screenshot_html = '<div class="thumbnail"></div>'

        # Create tag card
        tag_slug = slugify_tag(tag)
        subpage_name = os.path.join(output_dir, f"{dom_slug}_tag_{tag_slug}.html")

        html += f"""
                <a href="{dom_slug}_tag_{tag_slug}.html">
                    <div class="tag-card">
                        {screenshot_html}
                        <div class="content">
                            <h3>{tag}</h3>
                            <div class="count">{len(items)} findings</div>
                            <div class="status-badges">
        """
        
        if status_counts['new'] > 0:
            html += f'<span class="badge new">{status_counts["new"]} new</span>'
        if status_counts['changed'] > 0:
            html += f'<span class="badge changed">{status_counts["changed"]} changed</span>'
        if status_counts['existing'] > 0:
            html += f'<span class="badge existing">{status_counts["existing"]} existing</span>'
        
        html += """
                            </div>
                        </div>
                    </div>
                </a>
        """

        # Generate the sub-page
        make_enhanced_subpage_for_tag(domain, tag, items, subpage_name, output_dir, dom_slug)

    html += """
            </div>
            </div>
    </body>
    </html>
    """

    # Ensure the directory exists
    os.makedirs(os.path.dirname(tag_index_file), exist_ok=True)

    with open(tag_index_file, "w") as f:
        f.write(html)

    print(f"[+] Tag index for '{domain}' saved to: {tag_index_file}")
    return tag_index_file


def make_enhanced_subpage_for_tag(domain, tag, items, subpage_name, output_dir, dom_slug=None):
    """Generate an enhanced subpage for a specific tag"""
    if not dom_slug:
        dom_slug = slugify_tag(domain)
    
    # Sort items by most interesting first: new -> changed -> existing
    sorted_items = sorted(items, key=lambda x: {
        'new': 0,
        'changed': 1,
        'existing': 2
    }.get(x.get('finding_status', 'existing'), 3))
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(subpage_name), exist_ok=True)
    
    with open(subpage_name, "w") as f:
        # Page header and CSS
        f.write(f"""<!DOCTYPE html>
<html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{tag} - {domain}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
        <style>
            body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                padding: 0;
            margin: 0;
                background-color: #f5f5f7;
        }}
        .card {{
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border: none;
            border-radius: 10px;
        }}
        .card-header {{
            background-color: #f8f9fa;
            border-bottom: none;
            padding: 15px;
        }}
        .status-new {{
            background-color: #28a745 !important;
        }}
        .status-changed {{
            background-color: #17a2b8 !important;
        }}
        .status-existing {{
            background-color: #6c757d !important;
        }}
        .tech-badge {{
            margin-right: 5px;
            margin-bottom: 5px;
        }}
        .screenshot-container {{
            text-align: center;
            margin-bottom: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 10px;
        }}
        .screenshot-container img {{
            max-width: 100%;
            border: 1px solid #ddd;
            border-radius: 5px;
        }}
        .tech-category-item {{
            padding: 6px 12px;
            border-radius: 15px;
            background-color: #e9ecef;
            font-size: 13px;
                display: inline-flex;
                align-items: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-right: 8px;
            margin-bottom: 8px;
        }}
        .tech-category-item i {{
            margin-right: 5px;
        }}
        .main-header {{
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            color: white;
            padding: 30px 0;
            margin-bottom: 0;
            text-align: center;
        }}
        .breadcrumb-container {{
            background-color: white;
            padding: 10px 0;
            border-bottom: 1px solid #eee;
            margin-bottom: 30px;
        }}
        .filter-container {{
            background-color: #fff;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            position: sticky;
            top: 15px;
            z-index: 1000;
        }}
        .filter-row {{
            display: flex;
            gap: 15px;
        }}
        .filter-item {{
            flex: 1;
        }}
        .meta-info {{
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 10px 15px;
            margin-bottom: 15px;
            }}
        </style>
    </head>
    <body>
    <header class="main-header">
                <h1>{tag}</h1>
        <p>Findings for {domain}</p>
    </header>
    
    <div class="breadcrumb-container">
        <div class="container">
            <nav aria-label="breadcrumb">
                <ol class="breadcrumb mb-0">
                    <li class="breadcrumb-item"><a href="dashboard.html">Dashboard</a></li>
                    <li class="breadcrumb-item"><a href="dashboard.html">{domain}</a></li>
                    <li class="breadcrumb-item"><a href="{domain}_tags.html">Tags</a></li>
                    <li class="breadcrumb-item active">{tag}</li>
                </ol>
            </nav>
            </div>
        </div>
        
        <div class="container">
        <div class="filter-container">
            <div class="filter-row">
                <div class="filter-item">
                    <input type="text" class="form-control" id="searchInput" placeholder="Search findings...">
                </div>
                <div class="filter-item">
                    <select class="form-select" id="statusFilter">
                        <option value="all">All Statuses</option>
                        <option value="new">New</option>
                        <option value="changed">Changed</option>
                        <option value="existing">Existing</option>
                    </select>
                </div>
                <div class="filter-item">
                    <select class="form-select" id="tagFilter">
                        <option value="all">All Tags</option>
                    </select>
                </div>
                <div class="filter-item">
                    <button class="btn btn-primary w-100" id="resetFilters">Reset Filters</button>
                </div>
            </div>
        </div>
        
        <!-- Add stats row -->
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-body">
                        <div class="d-flex flex-wrap justify-content-between">
                            <!-- Download stats -->
                            <div class="me-4 mb-2">
                                <h6 class="mb-1">Downloadable Files</h6>
                                <div class="d-flex align-items-center">
                                    <span class="badge bg-info me-2">
                                        <i class="fas fa-download me-1"></i> 
                                        {sum(1 for item in items if item.get('download_meta', {}).get('is_downloadable'))}
                                    </span>
                                    <button class="btn btn-sm btn-outline-info" type="button" data-bs-toggle="collapse" 
                                        data-bs-target="#downloadableDetails" aria-expanded="false">
                                        View Details
                                    </button>
                                </div>
                            </div>
                            
                            <!-- Secret stats -->
                            <div class="mb-2">
                                <h6 class="mb-1">Exposed Secrets</h6>
                                <div class="d-flex align-items-center">
                                    <span class="badge bg-danger me-2">
                                        <i class="fas fa-key me-1"></i> 
                                        {sum(1 for item in items if item.get('secrets'))}
                                    </span>
                                    <button class="btn btn-sm btn-outline-danger" type="button" data-bs-toggle="collapse" 
                                        data-bs-target="#secretsDetails" aria-expanded="false">
                                        View Details
                                    </button>
                                </div>
                            </div>


                            </div>
                            </div>
                </div>
            </div>
                            </div>
        

        
        <!-- Downloadable details -->
        <div class="collapse mb-4" id="downloadableDetails">
            <div class="card">
                <div class="card-header">
                    <h5>Downloadable Files</h5>
                            </div>
                <div class="card-body">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Path</th>
                                <th>Filename</th>
                                <th>Type</th>
                                <th>Size</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(''.join([f"<tr><td>{item.get('path', '/')}</td><td>{item.get('download_meta', {}).get('filename', 'unknown')}</td><td>{item.get('download_meta', {}).get('mime_type', 'unknown')}</td><td>{format_file_size(item.get('download_meta', {}).get('size_bytes', 0))}</td></tr>" for item in items if item.get('download_meta', {}).get('is_downloadable')]))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Secrets details -->
        <div class="collapse mb-4" id="secretsDetails">
            <div class="card">
                <div class="card-header">
                    <h5>Exposed Secrets</h5>
                        </div>
                <div class="card-body">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Path</th>
                                <th>Secret Type</th>
                                <th>Severity</th>
                                <th>Line</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(''.join([f"<tr><td>{item.get('path', '/')}</td><td>{secret.get('type', 'Unknown')}</td><td><span class='badge bg-{severity_to_color(secret.get('severity', 'medium'))}'>{secret.get('severity', 'medium').upper()}</span></td><td>{secret.get('line_number', 'N/A')}</td></tr>" for item in items for secret in item.get('secrets', []) if item.get('secrets')]))}
                        </tbody>
                    </table>
                    </div>
                </div>
        </div>
        

        
        <div class="findings-container">
""")
        
        # Add each finding
        for item in sorted_items:
            path = item.get('path', 'unknown')
            url = item.get('url', '')
            status = item.get('status', 200)
            length = item.get('length', 0)
            finding_status = item.get('finding_status', 'existing')
            
            # Handle root path display
            display_path = path
            if display_path == "/" or not display_path or display_path == "unknown":
                display_path = "(root)"
                
            # Determine status badge class
            status_class = {
                'new': 'status-new',
                'changed': 'status-changed',
                'existing': 'status-existing'
            }.get(finding_status, '')
            
            # Prepare badge content
            status_text = finding_status.capitalize()
            
            # Format screenshot path
            screenshot_html = ""
            screenshot_path = item.get('screenshot', '')
            if screenshot_path:
                rel_screenshot_path = os.path.relpath(screenshot_path, output_dir) if os.path.exists(screenshot_path) else ""
                if rel_screenshot_path:
                    screenshot_html = f'<div class="screenshot-container"><img src="{rel_screenshot_path}" alt="Screenshot of {url}" class="img-fluid"></div>'
                else:
                    screenshot_html = f'<div class="screenshot-container"><p class="text-muted">Screenshot not available</p></div>'
                    

                    
            # Format downloadable information
            download_html = ""
            download_meta = item.get('download_meta', {})
            if download_meta and download_meta.get('is_downloadable'):
                filename = download_meta.get('filename', 'unknown')
                mime_type = download_meta.get('mime_type', 'unknown')
                size_bytes = download_meta.get('size_bytes', 0)
                size_display = format_file_size(size_bytes)
                
                download_html = f"""
                <div class="mt-3">
                    <h6><i class="fas fa-download"></i> Downloadable Content</h6>
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong>Filename:</strong> {filename}</p>
                            <p><strong>MIME Type:</strong> {mime_type}</p>
                        </div>
                        <div class="col-md-6">
                            <p><strong>File Size:</strong> {size_display}</p>
                        </div>
                    </div>
                </div>
                """
            
            # Format secrets information
            secrets_html = ""
            secrets = item.get('secrets', [])
            if secrets:
                secrets_html = f"""
                <div class="secret-section">
                    <h6><i class="fas fa-key"></i> Secrets Detected ({len(secrets)})</h6>
                    <div class="secrets-list">
                    """
                    
                for secret in secrets:
                    secret_type = secret.get('type', 'Unknown')
                    secret_value = secret.get('value', '')
                    severity = secret.get('severity', 'medium')
                    line_number = secret.get('line_number', '')
                    
                    secrets_html += f"""
                    <div class="secret-item">
                        <div class="secret-type secret-{severity}">{secret_type} <span class="badge bg-secondary">Line {line_number}</span></div>
                        <div class="secret-value">{secret_value}</div>
                            </div>
                        """
                    
                secrets_html += "</div></div>"
            
            # Write the finding card
            f.write(f"""
            <div class="card mb-4 finding-card" data-status="{finding_status}" data-tag="{item.get('ai_tag', 'Other')}">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5><a href="{url}" target="_blank">{display_path}</a></h5>
                    <span class="badge {status_class} status-badge">{status_text}</span>
                                </div>
                <div class="card-body">
                    {screenshot_html}
                    
                    <div class="meta-info">
                        <div class="row">
                            <div class="col-md-4">
                                <p><strong>URL:</strong> <a href="{url}" target="_blank">{url}</a></p>
                                <p><strong>Status:</strong> <span class="badge bg-{'success' if 200 <= status < 300 else 'warning' if 300 <= status < 400 else 'danger'}">{status}</span></p>
                            </div>
                            <div class="col-md-4">
                                <p><strong>Size:</strong> <span>{length} bytes</span></p>
                                <p><strong>First Seen:</strong> {item.get('first_seen', 'Unknown')}</p>
                            </div>
                            <div class="col-md-4">
                                <p><strong>Finding Status:</strong> <span class="badge {status_class}">{status_text}</span></p>
                            </div>
                        </div>
                    </div>
                    
                    {download_html}
                    {secrets_html}
                </div>
            </div>
            """)
        
        # Close the HTML
        f.write("""
                        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Search and filter functionality
    document.addEventListener('DOMContentLoaded', function() {
            const searchInput = document.getElementById('searchInput');
            const statusFilter = document.getElementById('statusFilter');
            const tagFilter = document.getElementById('tagFilter');
            const resetButton = document.getElementById('resetFilters');
            const findingCards = document.querySelectorAll('.finding-card');
            
            // Populate tag filter with available tags
            const availableTags = new Set();
            findingCards.forEach(card => {
                const cardTag = card.dataset.tag;
                if (cardTag) {
                    availableTags.add(cardTag);
                }
            });
            
            // Add tag options to the filter
            availableTags.forEach(tag => {
                const option = document.createElement('option');
                option.value = tag;
                option.textContent = tag;
                tagFilter.appendChild(option);
            });
        
        function applyFilters() {
                const searchTerm = searchInput.value.toLowerCase();
            const statusValue = statusFilter.value;
                const tagValue = tagFilter.value;
                
                findingCards.forEach(card => {
                    const cardContent = card.textContent.toLowerCase();
                    const cardStatus = card.dataset.status;
                    const cardTag = card.dataset.tag;
                    
                    const matchesSearch = searchTerm === '' || cardContent.includes(searchTerm);
                    const matchesStatus = statusValue === 'all' || cardStatus === statusValue;
                    const matchesTag = tagValue === 'all' || cardTag === tagValue;
                    
                    card.style.display = (matchesSearch && matchesStatus && matchesTag) ? 'block' : 'none';
                });
            }
            
            searchInput.addEventListener('input', applyFilters);
        statusFilter.addEventListener('change', applyFilters);
            tagFilter.addEventListener('change', applyFilters);
            
            resetButton.addEventListener('click', function() {
                searchInput.value = '';
                statusFilter.value = 'all';
                tagFilter.value = 'all';
                applyFilters();
            });
    });
    </script>
</body>
</html>
""")
    
    logger.info(f"[+] Created enhanced subpage: {subpage_name} for tag={tag}")


def create_compliance_report(domain, findings, output_dir=HTML_REPORT_DIR):
    """Generate a compliance-style HTML report for a single domain."""
    os.makedirs(output_dir, exist_ok=True)
    filename = f"compliance_{domain.replace('.', '_')}.html"
    filepath = os.path.join(output_dir, filename)

    # Aggregate severity counts
    from utils.ai_analyzer import get_category_priority
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    severity_mapping = {
        "Critical": lambda p: p >= 9,
        "High": lambda p: 7 <= p <= 8,
        "Medium": lambda p: 4 <= p <= 6,
        "Low": lambda p: p <= 3,
    }

    for f in findings:
        priority = get_category_priority(f.get("ai_tag", "Other"))
        for sev, check in severity_mapping.items():
            if check(priority):
                severity_counts[sev] += 1
                break

    total_findings = len(findings)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset='utf-8'>
        <title>Compliance Report – {domain}</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin:0; padding:2rem; background:#fafafa; }}
            h1 {{ margin-top:0; }}
            table {{ width:100%; border-collapse:collapse; margin-bottom:2rem; }}
            th, td {{ padding:0.75rem 1rem; border:1px solid #e5e7eb; text-align:left; }}
            th {{ background:#f3f4f6; }}
            .severity-Critical {{ color:#dc2626; font-weight:600; }}
            .severity-High {{ color:#d97706; font-weight:600; }}
            .severity-Medium {{ color:#2563eb; font-weight:600; }}
            .severity-Low {{ color:#065f46; font-weight:600; }}
        </style>
    </head>
    <body>
        <h1>Compliance-Style Report – {domain}</h1>
        <p><em>Generated {generated}</em></p>

        <h2>Executive Summary</h2>
        <p>Total Findings: <strong>{total_findings}</strong></p>
        <ul>
            <li>Critical: {severity_counts['Critical']}</li>
            <li>High: {severity_counts['High']}</li>
            <li>Medium: {severity_counts['Medium']}</li>
            <li>Low: {severity_counts['Low']}</li>
        </ul>

        <h2>Risk Matrix</h2>
        <table>
            <tr><th>Severity</th><th>Count</th><th>Recommended Remediation Timeline</th></tr>
            <tr><td class='severity-Critical'>Critical</td><td>{severity_counts['Critical']}</td><td>24 hours</td></tr>
            <tr><td class='severity-High'>High</td><td>{severity_counts['High']}</td><td>3 days</td></tr>
            <tr><td class='severity-Medium'>Medium</td><td>{severity_counts['Medium']}</td><td>7 days</td></tr>
            <tr><td class='severity-Low'>Low</td><td>{severity_counts['Low']}</td><td>30 days</td></tr>
        </table>

        <h2>Detailed Findings</h2>
        <table>
            <tr>
                <th>URL</th>
                <th>Status</th>
                <th>Category</th>
                <th>Severity</th>
                <th>First Seen</th>
                <th>Last Seen</th>
            </tr>
    """

    # Add finding rows
    from utils.db_handler import get_finding_status
    for f in findings:
        status = f.get('finding_status', 'unknown').capitalize()
        category = f.get('ai_tag', 'Other')
        priority = get_category_priority(category)
        if priority >= 9:
            severity = "Critical"
        elif priority >= 7:
            severity = "High"
        elif priority >= 4:
            severity = "Medium"
        else:
            severity = "Low"
        sev_class = f"severity-{severity}"
        finding_status = get_finding_status(f['url'])
        first_seen = finding_status.get('first_seen', '') if finding_status else ''
        last_seen = finding_status.get('last_seen', '') if finding_status else ''

        html += f"<tr class='{sev_class}'><td>{f['url']}</td><td>{status}</td><td>{category}</td><td>{severity}</td><td>{first_seen}</td><td>{last_seen}</td></tr>"

    html += """
        </table>
    </body>
    </html>
    """

    with open(filepath, 'w') as fp:
        fp.write(html)

    return filepath

def _generate_security_posture_html(domain, posture_data):
    """Generate HTML for the security posture section of a domain card"""
    
    risk_rating = posture_data.get("risk_rating", "UNKNOWN")
    risk_score = posture_data.get("risk_score", "?/10")
    summary = posture_data.get("summary", "No security posture data available")
    recommendations = posture_data.get("recommendations", [])
    cve_summary = posture_data.get("cve_summary", "")
    cves = posture_data.get("cves", [])
    missing_headers = posture_data.get("missing_headers", [])
    
    # Set risk color based on rating
    risk_color = "#6c757d"  # Default gray
    if risk_rating == "CRITICAL":
        risk_color = "#dc3545"  # Red
    elif risk_rating == "HIGH":
        risk_color = "#fd7e14"  # Orange
    elif risk_rating == "MEDIUM":
        risk_color = "#ffc107"  # Yellow
    elif risk_rating == "LOW":
        risk_color = "#28a745"  # Green
    
    recommendations_html = ""
    if recommendations:
        recommendations_html = "<ul class='recommendations-list'>"
        for rec in recommendations:
            recommendations_html += f"<li>✅ {rec}</li>"
        recommendations_html += "</ul>"
    
    # Format missing headers list if any
    missing_headers_html = ""
    if missing_headers:
        missing_headers_html = """
        <div class="mt-3">
            <h6>Missing Security Headers:</h6>
            <ul class="missing-headers-list">
        """
        for header in missing_headers:
            missing_headers_html += f"<li>{header}</li>"
        missing_headers_html += "</ul></div>"
    
    # Generate CVE details table if CVEs exist
    cve_details_html = ""
    if cves:
        cve_details_html = """
        <div class="mt-3">
            <div class="cve-header" onclick="toggleCveDetails(this)">
                <h6><i class="fas fa-caret-right"></i> CVE Details</h6>
            </div>
            <div class="cve-details" style="display:none;">
                <table class="table table-sm table-bordered">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Package</th>
                            <th>Version</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for cve in cves:
            severity = cve.get("severity", "").lower()
            severity_class = ""
            if "critical" in severity:
                severity_class = "text-white bg-danger"
            elif "high" in severity:
                severity_class = "text-white bg-warning"
            elif "medium" in severity:
                severity_class = "text-dark bg-info"
            else:
                severity_class = "text-dark bg-light"
                
            cve_details_html += f"""
            <tr>
                <td><a href="https://nvd.nist.gov/vuln/detail/{cve['id']}" target="_blank">{cve['id']}</a></td>
                <td>{cve['package']}</td>
                <td>{cve['version']}</td>
                <td class="{severity_class}">{cve['severity']}</td>
            </tr>
            """
        
        cve_details_html += """
                    </tbody>
                </table>
            </div>
        </div>
        """
    
    # Construct the full security posture HTML
    html = f"""
    <div class="security-posture">
        <div class="d-flex justify-content-between align-items-center mb-2">
            <h5>🛡️ Security Posture</h5>
            span class="badge" style="background-color: {risk_color}; font-size: 1rem;">{risk_rating} {risk_score}</span>
        </div>
        
        <p class="security-summary">{summary}</p>
        
        {recommendations_html}
        
        {missing_headers_html}
        
        {cve_details_html if cve_details_html else ''}
        
        <div class="text-center mt-3 mb-2">
                            <a href="{domain}_findings.html" class="btn btn-primary">View Findings</a>
                <a href="{domain}_tags.html" class="btn btn-secondary ms-2">View by Tag</a>
        </div>
    </div>
    """
    
    return html

def export_domain_findings(domain, findings, output_dir=None):
    """
    Export findings for a domain to an HTML file
    """
    if not output_dir:
        output_dir = "results/html"
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Handle domains with paths by creating a safe filename
    from main_optimized import safe_filename
    safe_domain = safe_filename(domain)
    output_path = os.path.join(output_dir, f"{safe_domain}_findings.html")
    
    # Sort findings - new first, then changed, then existing
    findings_sorted = sorted(findings, key=lambda x: {
        'new': 0,
        'changed': 1,
        'existing': 2
    }.get(x.get('finding_status', 'existing'), 3))
    
    # Get all unique tags from findings
    all_tags = set()
    for finding in findings:
        all_tags.add(finding.get('ai_tag', 'Other'))
    
    with open(output_path, "w") as f:
        # Write HTML header
        f.write(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Findings for {domain}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 0;
            margin: 0;
            background-color: #f5f5f7;
        }}
        .card {{
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            border: none;
            border-radius: 10px;
        }}
        .card-header {{
            background-color: #f8f9fa;
            border-bottom: none;
            padding: 15px;
        }}
        .card-title {{
            margin-bottom: 0;
        }}
        .status-badge {{
            margin-left: 10px;
        }}
        .screenshot-container {{
            text-align: center;
            margin-bottom: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 10px;
        }}
        .screenshot-container img {{
            max-width: 100%;
            border: 1px solid #ddd;
            border-radius: 5px;
        }}
        .meta-info {{
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 10px 15px;
            margin-bottom: 15px;
        }}
        .meta-info p {{
            margin-bottom: 5px;
        }}
        .tech-badge {{
            margin-right: 5px;
            margin-bottom: 5px;
            display: inline-block;
        }}
        .status-new {{
            background-color: #28a745 !important;
        }}
        .status-changed {{
            background-color: #17a2b8 !important;
        }}
        .status-existing {{
            background-color: #6c757d !important;
        }}
        .header-list {{
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 10px;
        }}
        .header-item {{
            padding: 5px 0;
            border-bottom: 1px solid #eee;
        }}
        .header-item:last-child {{
            border-bottom: none;
        }}
        .header-name {{
            font-weight: bold;
        }}
        .container {{
            max-width: 1200px;
        }}
        .tag-badge {{
            font-size: 85%;
        }}
        .vulnerability-section {{
            background-color: #fff3cd;
            padding: 10px;
            border-radius: 5px;
            border-left: 4px solid #ffc107;
            margin-top: 15px;
        }}
        .secret-section {{
            background-color: #f8d7da;
            padding: 10px;
            border-radius: 5px;
            border-left: 4px solid #dc3545;
            margin-top: 15px;
        }}
        .downloadable-section {{
            background-color: #d1ecf1;
            padding: 10px;
            border-radius: 5px;
            border-left: 4px solid #17a2b8;
            margin-top: 15px;
        }}
        .secret-item {{
            padding: 8px;
            margin-bottom: 8px;
            border-bottom: 1px solid #f1b0b7;
        }}
        .secret-item:last-child {{
            border-bottom: none;
            margin-bottom: 0;
        }}
        .secret-type {{
            font-weight: bold;
        }}
        .secret-value {{
            font-family: monospace;
            background-color: rgba(0,0,0,0.05);
            padding: 3px 6px;
            border-radius: 3px;
            word-break: break-all;
        }}
        .secret-critical {{
            color: #721c24;
        }}
        .secret-high {{
            color: #e65100;
        }}
        .secret-medium {{
            color: #856404;
        }}
        .secret-low {{
            color: #155724;
        }}
        .main-header {{
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            color: white;
            padding: 30px 0;
            margin-bottom: 0;
            text-align: center;
        }}
        .breadcrumb-container {{
            background-color: white;
            padding: 10px 0;
            border-bottom: 1px solid #eee;
            margin-bottom: 30px;
        }}
        .filter-container {{
            background-color: #fff;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            position: sticky;
            top: 15px;
            z-index: 1000;
        }}
        .filter-row {{
            display: flex;
            gap: 15px;
        }}
        .filter-item {{
            flex: 1;
        }}
    </style>
</head>
<body>
    <header class="main-header">
        <h1>Security Findings</h1>
        <p>Comprehensive findings for {domain}</p>
    </header>
    
    <div class="breadcrumb-container">
        <div class="container">
            <nav aria-label="breadcrumb">
                <ol class="breadcrumb mb-0">
                    <li class="breadcrumb-item"><a href="dashboard.html">Dashboard</a></li>
                    <li class="breadcrumb-item"><a href="dashboard.html">{domain}</a></li>
                    <li class="breadcrumb-item active">Findings</li>
                </ol>
            </nav>
        </div>
        </div>
        
    <div class="container">
        <div class="filter-container">
            <div class="filter-row">
                <div class="filter-item">
                    <input type="text" class="form-control" id="searchInput" placeholder="Search findings...">
            </div>
                <div class="filter-item">
                    <select class="form-select" id="statusFilter">
                        <option value="all">All Statuses</option>
                    <option value="new">New</option>
                    <option value="changed">Changed</option>
                    <option value="existing">Existing</option>
                </select>
                </div>
                <div class="filter-item">
                    <select class="form-select" id="tagFilter">
                        <option value="all">All Tags</option>
                    </select>
                </div>
                <div class="filter-item">
                    <button class="btn btn-primary w-100" id="resetFilters">Reset Filters</button>
                </div>
            </div>
        </div>
        
        <!-- Add stats row -->
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-body">
                        <div class="d-flex flex-wrap justify-content-between">
                            <!-- Download stats -->
                            <div class="me-4 mb-2">
                                <h6 class="mb-1">Downloadable Files</h6>
                                <div class="d-flex align-items-center">
                                    <span class="badge bg-info me-2">
                                        <i class="fas fa-download me-1"></i> 
                                        {sum(1 for finding in findings if finding.get('download_meta', {}).get('is_downloadable'))}
                                    </span>
                                    <button class="btn btn-sm btn-outline-info" type="button" data-bs-toggle="collapse" 
                                        data-bs-target="#downloadableDetails" aria-expanded="false">
                                        View Details
                                    </button>
                                </div>
                            </div>
                            
                            <!-- Secret stats -->
                            <div class="mb-2">
                                <h6 class="mb-1">Exposed Secrets</h6>
                                <div class="d-flex align-items-center">
                                    <span class="badge bg-danger me-2">
                                        <i class="fas fa-key me-1"></i> 
                                        {sum(1 for finding in findings if finding.get('secrets'))}
                                    </span>
                                    <button class="btn btn-sm btn-outline-danger" type="button" data-bs-toggle="collapse" 
                                        data-bs-target="#secretsDetails" aria-expanded="false">
                                        View Details
                                    </button>
                                </div>
                            </div>


                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Downloadable details -->
        <div class="collapse mb-4" id="downloadableDetails">
            <div class="card">
                <div class="card-header">
                    <h5>Downloadable Files</h5>
                </div>
                <div class="card-body">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Path</th>
                                <th>Filename</th>
                                <th>Type</th>
                                <th>Size</th>
                            </tr>
                        </thead>
                        <tbody>
                            {(''.join([f"<tr><td>{item.get('path', '/')}</td><td>{item.get('download_meta', {}).get('filename', 'unknown')}</td><td>{item.get('download_meta', {}).get('mime_type', 'unknown')}</td><td>{format_file_size(item.get('download_meta', {}).get('size_bytes', 0))}</td></tr>" for item in findings if item.get('download_meta', {}).get('is_downloadable')]))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Secrets details -->
        <div class="collapse mb-4" id="secretsDetails">
            <div class="card">
                <div class="card-header">
                    <h5>Exposed Secrets</h5>
                </div>
                <div class="card-body">
                    <table class="table table-striped">
                    <thead>
                        <tr>
                                <th>Path</th>
                                <th>Secret Type</th>
                                <th>Severity</th>
                                <th>Line</th>
                        </tr>
                    </thead>
                    <tbody>
                            {(''.join([f"<tr><td>{finding.get('path', '/')}</td><td>{secret.get('type', 'Unknown')}</td><td><span class='badge bg-{severity_to_color(secret.get('severity', 'medium'))}'>{secret.get('severity', 'medium').upper()}</span></td><td>{secret.get('line_number', 'N/A')}</td></tr>" for finding in findings for secret in finding.get('secrets', []) if finding.get('secrets')]))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        

        
        <div class="findings-container">
""")

        # Write findings
        for finding in findings_sorted:
            path = finding.get('path', 'unknown')
            url = finding.get('url', f'https://{domain}/{path}')
            status = finding.get('status', 'unknown')
            length = finding.get('length', 'Unknown')
            finding_status = finding.get('finding_status', 'existing')
            screenshot_path = finding.get('screenshot', '')
            headers = finding.get('headers', {})
            tag = finding.get('ai_tag', 'Other')
            
            # Handle root path display
            display_path = path
            if display_path == "/" or not display_path or display_path == "unknown":
                display_path = "(root)"

            # Determine status badge class
            status_class = {
                'new': 'status-new',
                'changed': 'status-changed',
                'existing': 'status-existing'
            }.get(finding_status, '')
            
            # Prepare badge content
            status_text = finding_status.capitalize()

            # Format screenshot path - use relative path for display
            screenshot_html = ""
            if screenshot_path:
                rel_screenshot_path = os.path.relpath(screenshot_path, output_dir) if os.path.exists(screenshot_path) else ""
                if rel_screenshot_path:
                    screenshot_html = f'<div class="screenshot-container"><img src="{rel_screenshot_path}" alt="Screenshot of {url}" class="img-fluid"></div>'
                else:
                    screenshot_html = f'<div class="screenshot-container"><p class="text-muted">Screenshot not available</p></div>'

            # Format headers
            headers_html = ""
            if headers:
                headers_html = '<div class="header-list mt-3"><h6>Response Headers</h6>'
                for header_name, header_value in headers.items():
                    headers_html += f'<div class="header-item"><span class="header-name">{header_name}:</span> {header_value}</div>'
                headers_html += '</div>'
            

            

                    
            # Format downloadable information
            download_html = ""
            download_meta = finding.get('download_meta', {})
            if download_meta and download_meta.get('is_downloadable'):
                filename = download_meta.get('filename', 'unknown')
                mime_type = download_meta.get('mime_type', 'unknown')
                size_bytes = download_meta.get('size_bytes', 0)
                size_display = format_file_size(size_bytes)
                
                download_html = f"""
                <div class="downloadable-section">
                    <h6><i class="fas fa-download"></i> Downloadable Content</h6>
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong>Filename:</strong> {filename}</p>
                            <p><strong>MIME Type:</strong> {mime_type}</p>
                </div>
                        <div class="col-md-6">
                            <p><strong>File Size:</strong> {size_display}</p>
            </div>
                    </div>
                </div>
        """
        
            # Format secrets information
            secrets_html = ""
            secrets = finding.get('secrets', [])
            
            # Set empty tech and vuln HTML (removed during CVE/tech cleanup)
            tech_html = ""
            vuln_html = ""
            if secrets:
                secrets_html = f"""
                <div class="secret-section">
                    <h6><i class="fas fa-key"></i> Secrets Detected ({len(secrets)})</h6>
                    <div class="secrets-list">
                """
                
                for secret in secrets:
                    secret_type = secret.get('type', 'Unknown')
                    secret_value = secret.get('value', '')
                    severity = secret.get('severity', 'medium')
                    line_number = secret.get('line_number', '')
                    
                    secrets_html += f"""
                    <div class="secret-item">
                        <div class="secret-type secret-{severity}">{secret_type} <span class="badge bg-secondary">Line {line_number}</span></div>
                        <div class="secret-value">{secret_value}</div>
                    </div>
                    """
                
                secrets_html += "</div></div>"
            
            # Write the finding card
            f.write(f"""
            <div class="card mb-4 finding-card" data-status="{finding_status}" data-tag="{tag}">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5><a href="{url}" target="_blank">{display_path}</a></h5>
                    <span class="badge {status_class} status-badge">{status_text}</span>
                </div>
                <div class="card-body">
                    {screenshot_html}
                    
                    <div class="meta-info">
                        <div class="row">
                            <div class="col-md-4">
                                <p><strong>URL:</strong> <a href="{url}" target="_blank">{url}</a></p>
                                <p><strong>Status:</strong> <span class="badge bg-{'success' if 200 <= status < 300 else 'warning' if 300 <= status < 400 else 'danger'}">{status}</span></p>
            </div>
                            <div class="col-md-4">
                                <p><strong>Size:</strong> <span>{length} bytes</span></p>
                                <p><strong>First Seen:</strong> {finding.get('first_seen', 'Unknown')}</p>
        </div>
                            <div class="col-md-4">
                                <p><strong>AI Tag:</strong> <span class="badge bg-primary tag-badge">{tag}</span></p>
                            </div>
                        </div>
                    </div>
                    
                    {tech_html}
                    {vuln_html}
                    {download_html}
                    {secrets_html}
                    {headers_html}
        </div>
    </div>
            """)
        
        # Close the HTML
        f.write("""
        </div>
    </div>
    
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Search and filter functionality
    document.addEventListener('DOMContentLoaded', function() {
            const searchInput = document.getElementById('searchInput');
            const statusFilter = document.getElementById('statusFilter');
            const tagFilter = document.getElementById('tagFilter');
            const resetButton = document.getElementById('resetFilters');
            const findingCards = document.querySelectorAll('.finding-card');
            
            // Populate tag filter with available tags
            const availableTags = new Set();
            findingCards.forEach(card => {
                const cardTag = card.dataset.tag;
                if (cardTag) {
                    availableTags.add(cardTag);
                }
            });
            
            // Add tag options to the filter
            availableTags.forEach(tag => {
                const option = document.createElement('option');
                option.value = tag;
                option.textContent = tag;
                tagFilter.appendChild(option);
            });
            
            // Handle URL parameters for filtering
            const urlParams = new URLSearchParams(window.location.search);
            const statusParam = urlParams.get('status');
            const tagParam = urlParams.get('tag');
            
            // Apply URL parameters to filters
            if (statusParam) {
                statusFilter.value = statusParam;
            }
            if (tagParam) {
                tagFilter.value = tagParam;
            }
        
        function applyFilters() {
                const searchTerm = searchInput.value.toLowerCase();
            const statusValue = statusFilter.value;
                const tagValue = tagFilter.value;
                
                findingCards.forEach(card => {
                    const cardContent = card.textContent.toLowerCase();
                    const cardStatus = card.dataset.status;
                    const cardTag = card.dataset.tag;
                    
                    const matchesSearch = searchTerm === '' || cardContent.includes(searchTerm);
                    const matchesStatus = statusValue === 'all' || cardStatus === statusValue;
                    const matchesTag = tagValue === 'all' || cardTag === tagValue;
                    
                    card.style.display = (matchesSearch && matchesStatus && matchesTag) ? 'block' : 'none';
                });
            }
            
            searchInput.addEventListener('input', applyFilters);
        statusFilter.addEventListener('change', applyFilters);
            tagFilter.addEventListener('change', applyFilters);
            
            resetButton.addEventListener('click', function() {
                searchInput.value = '';
                statusFilter.value = 'all';
                tagFilter.value = 'all';
                applyFilters();
            });
            
            // Apply filters on page load if URL parameters are present
            if (statusParam || tagParam) {
                applyFilters();
            }
    });
    </script>
</body>
</html>
""")
    
    logger.info(f"Exported {len(findings)} findings for {domain} to {output_path}")
    return output_path

def format_file_size(size_bytes):
    """Format file size in human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

def severity_to_color(severity):
    """Convert severity string to Bootstrap color class"""
    severity_map = {
        "critical": "danger",
        "high": "warning",
        "medium": "info",
        "low": "secondary"
    }
    return severity_map.get(severity.lower(), "secondary")



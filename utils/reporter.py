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
from utils.tech_helpers import extract_tech_and_cves, aggregate_cves, severity_from_count
import re

# Set up logger
logger = logging.getLogger(__name__)

HTML_REPORT_DIR = "results/html"

# ------------------------------------------------------------
# Helper for CVE descriptions (OSV.dev) – cached in-memory so repeated
# look-ups are fast. We only fetch when building HTML and will silently
# ignore network failures.
# ------------------------------------------------------------


@lru_cache(maxsize=2048)
def _fetch_cve_summary(cve_id: str) -> str:
    """Return short summary/description for the given CVE/GHSA id."""
    if not cve_id:
        return ""
    url = f"https://api.osv.dev/v1/vuln/{cve_id}"
    try:
        resp = requests.get(url, timeout=6)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("summary") or (data.get("details") or "")[:200]
    except Exception:
        pass
    return ""

def _slugify_name(value: str) -> str:
    """Return a filesystem- and URL-safe slug for arbitrary strings (domains, tags, etc.)."""
    # Remove URL scheme for domains
    value = re.sub(r"^[a-zA-Z]+://", "", value)
    # Replace non-alphanum (except dot, dash, underscore) with underscore
    value = re.sub(r"[^0-9A-Za-z._-]+", "_", value)
    # Collapse consecutive underscores
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "item"

def create_dashboard(all_domains_data, is_update=False):
    """
    Create a main dashboard that shows all domains and their findings
    
    Parameters:
    - all_domains_data: Dictionary mapping domains to their findings
    - is_update: If True, indicates this is an update to an existing dashboard
    """
    os.makedirs(HTML_REPORT_DIR, exist_ok=True)
    
    dashboard_file = os.path.join(HTML_REPORT_DIR, "dashboard.html")
    
    spark_svg = ""  # timeline placeholder

    # Aggregate statistics
    total_domains = len(all_domains_data)
    total_findings = sum(len(findings) for findings in all_domains_data.values())
    
    # Count by status and category across all domains
    global_status_counts = defaultdict(int)
    global_category_counts = defaultdict(int)
    global_secret_count   = 0
    # Will compute global CVE count later
    high_priority_findings = []
    
    for domain, findings in all_domains_data.items():
        for finding in findings:
            status = finding.get('finding_status', 'unknown')
            global_status_counts[status] += 1
            
            category = finding.get('ai_tag', 'Other')
            global_category_counts[category] += 1

            # Count secrets at finding level
            dm = finding.get('download_meta') or {}
            secret_cnt = len(dm.get('th_secrets', [])) + len(dm.get('potential_secrets', []))
            global_secret_count += secret_cnt
            
            # Collect high priority findings
            from utils.ai_analyzer import get_category_priority
            priority = get_category_priority(category)
            if priority >= 7:
                high_priority_findings.append({
                    'domain': domain,
                    'url': finding['url'],
                    'category': category,
                    'status': status,
                    'priority': priority,
                    'screenshot': finding.get('screenshot', '')
                })
    
    # Sort high priority findings
    high_priority_findings.sort(key=lambda x: (-x['priority'], x['domain'], x['url']))

    # ------------------------------------------------------------
    # Global CVE and secret summary across all findings
    # ------------------------------------------------------------
    all_findings_list = [f for findings in all_domains_data.values() for f in findings if f]
    global_cve_total = aggregate_cves(all_findings_list)["total"]
    
    # Calculate global secret count
    global_secret_count = 0
    for f in all_findings_list:
        dm = f.get('download_meta') or {}
        secret_cnt = len(dm.get('th_secrets', [])) + len(dm.get('potential_secrets', []))
        global_secret_count += secret_cnt
    
    # Build dashboard HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>DirHunter AI - Security Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="refresh" content="60">
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f5f5f7;
                color: #1d1d1f;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 2rem;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .header h1 {{
                margin: 0;
                font-size: 2.5rem;
                font-weight: 600;
            }}
            .header .subtitle {{
                margin-top: 0.5rem;
                opacity: 0.9;
                font-size: 1.1rem;
            }}
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 2rem;
            }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }}
            .stat-card {{
                background: white;
                padding: 1.5rem;
                border-radius: 12px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                text-align: center;
            }}
            .stat-card h2 {{
                margin: 0;
                font-size: 2.5rem;
                font-weight: 700;
                color: #4f46e5;
            }}
            .stat-card p {{
                margin: 0.5rem 0 0 0;
                color: #6b7280;
                font-size: 1rem;
            }}
            .domain-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }}
            .domain-card {{
                background: white;
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                transition: transform 0.2s;
            }}
            .domain-card:hover {{
                transform: translateY(-4px);
                box-shadow: 0 8px 16px rgba(0,0,0,0.12);
            }}
            .domain-card .header {{
                padding: 1.5rem;
                background: #f9fafb;
                border-bottom: 1px solid #e5e7eb;
            }}
            .domain-card .header h3 {{
                margin: 0;
                font-size: 1.25rem;
                font-weight: 600;
                color: #111827;
            }}
            .domain-card .content {{
                padding: 1.5rem;
            }}
            .domain-card .stats {{
                display: flex;
                justify-content: space-between;
                margin-bottom: 1rem;
            }}
            .domain-card .stat {{
                text-align: center;
            }}
            .domain-card .stat .value {{
                font-size: 1.5rem;
                font-weight: 700;
                color: #4f46e5;
            }}
            .domain-card .stat .label {{
                font-size: 0.875rem;
                color: #6b7280;
            }}
            .domain-card .tags {{
                display: flex;
                flex-wrap: wrap;
                gap: 0.5rem;
                margin-bottom: 1rem;
            }}
            .domain-card .tag {{
                background: #f3f4f6;
                color: #4b5563;
                padding: 0.25rem 0.75rem;
                border-radius: 9999px;
                font-size: 0.75rem;
                font-weight: 500;
            }}
            .domain-card .view-btn {{
                display: block;
                width: 100%;
                padding: 0.75rem;
                background: #4f46e5;
                color: white;
                text-align: center;
                text-decoration: none;
                border-radius: 6px;
                font-weight: 500;
                transition: background-color 0.2s;
            }}
            .domain-card .view-btn:hover {{
                background: #4338ca;
            }}
            .priority-section {{
                background: white;
                border-radius: 12px;
                padding: 1.5rem;
                margin-bottom: 2rem;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            }}
            .priority-section h2 {{
                margin-top: 0;
                margin-bottom: 1.5rem;
                font-size: 1.5rem;
                font-weight: 600;
                color: #111827;
            }}
            .priority-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 1.5rem;
            }}
            .priority-card {{
                background: #f9fafb;
                border-radius: 8px;
                overflow: hidden;
                border-left: 4px solid #4f46e5;
            }}
            .priority-card .thumbnail {{
                width: 100%;
                height: 180px;
                object-fit: cover;
                background: #e5e7eb;
            }}
            .priority-card .content {{
                padding: 1rem;
            }}
            .priority-card h3 {{
                margin: 0 0 0.5rem 0;
                font-size: 1rem;
                font-weight: 500;
            }}
            .priority-card p {{
                margin: 0;
                font-size: 0.875rem;
                color: #6b7280;
            }}
            .priority-card .meta {{
                display: flex;
                justify-content: space-between;
                margin-top: 0.75rem;
                font-size: 0.75rem;
            }}
            .priority-card .domain {{
                color: #6b7280;
            }}
            .priority-card .priority {{
                font-weight: 500;
                color: #4f46e5;
            }}
            .priority-card .priority.high {{
                color: #dc2626;
            }}
            .status-badge {{
                display: inline-block;
                padding: 0.25rem 0.5rem;
                border-radius: 9999px;
                font-size: 0.75rem;
                font-weight: 500;
                text-transform: uppercase;
            }}
            .status-new {{
                background: #dcfce7;
                color: #166534;
            }}
            .status-changed {{
                background: #fef3c7;
                color: #92400e;
            }}
            .status-existing {{
                background: #e0e7ff;
                color: #3730a3;
            }}
            .status-unknown {{
                background: #f3f4f6;
                color: #4b5563;
            }}
            .search-box {{
                width: 100%;
                padding: 1rem;
                margin-bottom: 2rem;
                border: 1px solid #e5e7eb;
                border-radius: 8px;
                font-size: 1rem;
                background: white;
            }}
            .filter-bar {{
                display: flex;
                gap: 0.5rem;
                margin-bottom: 2rem;
                flex-wrap: wrap;
            }}
            .filter-btn {{
                padding: 0.5rem 1rem;
                background: #f3f4f6;
                border: none;
                border-radius: 6px;
                font-size: 0.875rem;
                font-weight: 500;
                color: #4b5563;
                cursor: pointer;
                transition: all 0.2s;
            }}
            .filter-btn:hover {{
                background: #e5e7eb;
            }}
            .filter-btn.active {{
                background: #4f46e5;
                color: white;
            }}
            .last-updated {{
                text-align: center;
                margin-top: 2rem;
                color: #6b7280;
                font-size: 0.875rem;
            }}
            .scan-status {{
                background: #fef3c7;
                color: #92400e;
                padding: 0.75rem;
                border-radius: 6px;
                margin-bottom: 1.5rem;
                text-align: center;
                font-weight: 500;
            }}
            .scan-status.completed {{
                background: #dcfce7;
                color: #166534;
            }}
            .domain-card .status-indicator {{
                display: inline-block;
                width: 10px;
                height: 10px;
                border-radius: 50%;
                margin-right: 0.5rem;
            }}
            .domain-card .status-indicator.completed {{
                background: #22c55e;
            }}
            .domain-card .status-indicator.scanning {{
                background: #f59e0b;
            }}
            .domain-card .status-text {{
                font-size: 0.75rem;
                color: #6b7280;
                display: flex;
                align-items: center;
                margin-top: 0.5rem;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="container">
                <h1>DirHunter AI - Security Dashboard</h1>
                <div class="subtitle">
                    Automated Directory Scanning & Security Analysis
                </div>
            </div>
        </div>
        
        <div class="container">
            <div class="scan-status{' completed' if not is_update else ''}">
                {f"Scan completed - {total_domains} domains analyzed" if not is_update else f"Scan in progress - {total_domains} domains processed so far"}
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h2>{total_domains}</h2>
                    <p>Domains Scanned</p>
                </div>
                <div class="stat-card">
                    <h2>{total_findings}</h2>
                    <p>Total Findings</p>
                </div>
                <div class="stat-card">
                    <h2>{global_status_counts.get('new', 0)}</h2>
                    <p>New Findings</p>
                </div>
                <div class="stat-card">
                    <h2>{global_cve_total}</h2>
                    <p>Unique Vulnerabilities</p>
                </div>
                <div class="stat-card">
                    <h2>{global_secret_count}</h2>
                    <p>Potential Secrets</p>
                </div>
            </div>
            
            <input type="text" class="search-box" id="searchInput" placeholder="Search domains...">
            
            <div class="filter-bar">
                <button class="filter-btn active" data-filter="all">All Domains</button>
                <button class="filter-btn" data-filter="new-findings">New Findings</button>
                <button class="filter-btn" data-filter="with-cves">With CVEs</button>
                <button class="filter-btn" data-filter="with-secrets">With Secrets</button>
            </div>
            
            <div class="domain-grid" id="domainGrid">
    """
    
    # Add domain cards
    for domain, findings in all_domains_data.items():
        if not findings:
            continue
            
        # Calculate domain stats
        total_domain_findings = len(findings)
        new_findings = sum(1 for f in findings if f.get('finding_status') == 'new')
        changed_findings = sum(1 for f in findings if f.get('finding_status') == 'changed')
        
        # Get domain tags
        domain_tags = set()
        for f in findings:
            tag = f.get('ai_tag', 'Other')
            if tag != 'Other' and len(domain_tags) < 5:  # Limit to 5 tags
                domain_tags.add(tag)
        
        # Count CVEs and secrets
        domain_secret_count = 0
        
        # Use the aggregate_cves function to get unique CVE count
        domain_cve_count = aggregate_cves(findings)["total"]
        
        for f in findings:
            
            # Count secrets
            dm = f.get('download_meta') or {}
            secret_cnt = len(dm.get('th_secrets', [])) + len(dm.get('potential_secrets', []))
            domain_secret_count += secret_cnt
        
        # Create slug for linking
        dom_slug = _slugify_name(domain)
        
        html += f"""
                <div class="domain-card" 
                    data-domain="{domain}" 
                    data-new-findings="{new_findings}" 
                    data-cves="{domain_cve_count}" 
                    data-secrets="{domain_secret_count}">
                    <div class="header">
                        <h3>{domain}</h3>
                        <div class="status-text">
                            <span class="status-indicator completed"></span>
                            Scan completed
                        </div>
                    </div>
                    <div class="content">
                        <div class="stats">
                            <div class="stat">
                                <div class="value">{total_domain_findings}</div>
                                <div class="label">Findings</div>
                            </div>
                            <div class="stat">
                                <div class="value">{new_findings}</div>
                                <div class="label">New</div>
                            </div>
                            <div class="stat">
                                <div class="value">{domain_cve_count}</div>
                                <div class="label">Unique Vulnerabilities</div>
                            </div>
                            <div class="stat">
                                <div class="value">{domain_secret_count}</div>
                                <div class="label">Secrets</div>
                            </div>
                        </div>
                        <div class="tags">
        """
        
        # Add tags
        for tag in domain_tags:
            html += f'<span class="tag">{tag}</span>'
            
        html += f"""
                        </div>
                        <div class="view-button">
                            <a href="{dom_slug}_tags.html" class="button">View Details</a>
                        </div>
                    </div>
                </div>
        """
    
    # Close domain grid and add high priority findings section
    html += """
            </div>
            
            <div class="priority-section">
                <h2>High Priority Findings</h2>
                <div class="priority-grid">
    """
    
    # Add high priority findings
    for i, finding in enumerate(high_priority_findings):
        if i >= 6:  # Limit to 6 cards
            break
            
        screenshot = ""
        if finding['screenshot'] and os.path.exists(finding['screenshot']):
            screenshot = f'<img src="{os.path.relpath(finding["screenshot"], HTML_REPORT_DIR)}" class="thumbnail" alt="{finding["category"]}">'
            
        priority_class = "high" if finding['priority'] >= 9 else ""
        
        status_class = "status-unknown"
        if finding['status'] == 'new':
            status_class = "status-new"
        elif finding['status'] == 'changed':
            status_class = "status-changed"
        elif finding['status'] == 'existing':
            status_class = "status-existing"
            
        html += f"""
                <div class="priority-card">
                    {screenshot}
                    <div class="content">
                        <h3>{finding['category']}</h3>
                        <p>{finding['url']}</p>
                        <div class="meta">
                            <span class="domain">{finding['domain']}</span>
                            <span class="status-badge {status_class}">{finding['status']}</span>
                            <span class="priority {priority_class}">Priority: {finding['priority']}/10</span>
                        </div>
                    </div>
                </div>
        """
    
    # Close priority section and add last updated info
    html += """
                </div>
            </div>
            
            <div class="last-updated">
                Last updated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """
            </div>
        </div>
        
        <script>
            (function() {
                const searchInput = document.getElementById('searchInput');
                const domainGrid = document.getElementById('domainGrid');
                const domainCards = domainGrid.querySelectorAll('.domain-card');
                const filterBtns = document.querySelectorAll('.filter-btn');
                
                let currentFilter = 'all';
                
                function applyFilters() {
                    const searchTerm = searchInput.value.toLowerCase();
                    
                    domainCards.forEach(card => {
                        const domain = card.dataset.domain.toLowerCase();
                        let show = domain.includes(searchTerm);
                        
                        // Apply category filter
                        if (show && currentFilter !== 'all') {
                            switch(currentFilter) {
                                case 'new-findings':
                                    show = parseInt(card.dataset.newFindings) > 0;
                                    break;
                                case 'with-cves':
                                    show = parseInt(card.dataset.cves) > 0;
                                    break;
                                case 'with-secrets':
                                    show = parseInt(card.dataset.secrets) > 0;
                                    break;
                            }
                        }
                        
                        card.style.display = show ? '' : 'none';
                    });
                }

                searchInput.addEventListener('input', applyFilters);
                filterBtns.forEach(btn => {
                    btn.addEventListener('click', () => {
                        filterBtns.forEach(b => b.classList.remove('active'));
                        btn.classList.add('active');
                        currentFilter = btn.dataset.filter;
                        applyFilters();
                    });
                });
            })();
        </script>
    </body>
    </html>
    """
    
    # Save dashboard
    with open(dashboard_file, "w", encoding="utf-8") as f:
        f.write(html)
    
    print(f"[+] Dashboard {'updated' if is_update else 'created'}: {dashboard_file}")
    return dashboard_file


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
    
    # Calculate CVEs and secrets counts
    cve_count = 0
    secret_count = 0
    
    for f in findings:
        if f is None:
            continue
            
        # Count CVEs
        tech = f.get('tech', {})
        cve_count += tech.get('cve_vulns', 0)
        
        # Count secrets
        dm = f.get('download_meta', {})
        if dm:
            secret_count += len(dm.get('th_secrets', [])) + len(dm.get('potential_secrets', []))

    # Enhanced HTML with better styling
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{domain} - Security Findings</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f5f5f7;
                color: #1d1d1f;
            }}
            .header {{
                background: white;
                padding: 2rem;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 2rem;
            }}
            .header h1 {{
                margin: 0;
                font-size: 2rem;
                font-weight: 600;
            }}
            .header .breadcrumb {{
                margin-top: 0.5rem;
                color: #6b7280;
            }}
            .header .breadcrumb a {{
                color: #6366f1;
                text-decoration: none;
            }}
            .stats-cards {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                gap: 1rem;
                margin-bottom: 2rem;
            }}
            .stat-card {{
                background: white;
                padding: 1.5rem;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                text-align: center;
            }}
            .stat-card h2 {{
                margin: 0;
                font-size: 2rem;
                font-weight: 600;
            }}
            .stat-card p {{
                margin: 0.5rem 0 0;
                color: #6b7280;
            }}
            .new-stat {{
                color: #ef4444;
            }}
            .changed-stat {{
                color: #f59e0b;
            }}
            .existing-stat {{
                color: #10b981;
            }}
            #searchBox {{{{
                width: 100%;
                padding: 0.75rem 1rem;
                margin: 1rem 0 2rem;
                border: 1px solid #d1d5db;
                border-radius: 6px;
                font-size: 1rem;
            }}}}
            .hidden {{{{ display:none !important; }}}}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 2rem 2rem;
            }}
            .tag-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }}
            .tag-card {{
                background: white;
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                transition: transform 0.2s ease, box-shadow 0.2s ease;
                cursor: pointer;
                color: inherit;
                text-decoration: none;
                display: block;
            }}
            .tag-card:hover {{
                transform: translateY(-4px);
                box-shadow: 0 10px 15px rgba(0,0,0,0.1);
            }}
            .tag-card .thumbnail {{
                height: 160px;
                background-color: #f3f4f6;
                overflow: hidden;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .tag-card .thumbnail img {{
                width: 100%;
                height: 100%;
                object-fit: cover;
            }}
            .tag-card .content {{
                padding: 1.5rem;
            }}
            .tag-card h3 {{
                margin: 0;
                font-size: 1.25rem;
                font-weight: 600;
            }}
            .tag-card .count {{
                margin-top: 0.5rem;
                color: #6b7280;
            }}
            .tag-card .status-badges {{
                margin-top: 1rem;
                display: flex;
                flex-wrap: wrap;
                gap: 0.5rem;
            }}
            .badge {{
                font-size: 0.75rem;
                padding: 0.25rem 0.5rem;
                border-radius: 4px;
                font-weight: 500;
            }}
            .badge.new {{
                background-color: #fef2f2;
                color: #ef4444;
            }}
            .badge.changed {{
                background-color: #fffbeb;
                color: #f59e0b;
            }}
            .badge.existing {{
                background-color: #ecfdf5;
                color: #10b981;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="breadcrumb">
                <a href="dashboard.html">Dashboard</a> &gt; {domain}
            </div>
            <h1>{domain}</h1>
        </div>
        
        <div class="container">
            <!-- Domain statistics summary -->
            <div class="stats-cards">
                <div class="stat-card">
                    <h2>{total_count}</h2>
                    <p>Total Findings</p>
                </div>
                <div class="stat-card">
                    <h2 class="new-stat">{new_count}</h2>
                    <p>New Findings</p>
                </div>
                <div class="stat-card">
                    <h2 class="changed-stat">{changed_count}</h2>
                    <p>Changed Findings</p>
                </div>
                <div class="stat-card">
                    <h2 class="existing-stat">{existing_count}</h2>
                    <p>Existing Findings</p>
                </div>
                <div class="stat-card">
                    <h2>{cve_count}</h2>
                    <p>Vulnerabilities</p>
                </div>
                <div class="stat-card">
                    <h2>{secret_count}</h2>
                    <p>Secrets</p>
                </div>
            </div>
            
            <input type="text" id="searchBox" placeholder="Search findings...">
            
            <div class="tag-grid">
    """

    # Sort tags by priority
    from utils.ai_analyzer import get_category_priority
    sorted_tags = sorted(grouped.items(), key=lambda x: -get_category_priority(x[0]))

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
        subpage_name = f"{dom_slug}_tag_{tag_slug}.html"

        html += f"""
                <a href="{subpage_name}">
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

    html += f"""
            </div>
            <div style="text-align: center; color: #6b7280; margin-top: 2rem;">
                Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S UTC')}
            </div>
        </div>
        <script>
        const searchBox = document.getElementById('searchBox');
        searchBox?.addEventListener('input', function() {{{{
            const q = this.value.toLowerCase();
            document.querySelectorAll('.tag-card').forEach(card => {{{{
                const text = card.innerText.toLowerCase();
                if(q === '' || text.indexOf(q) !== -1) {{{{
                    card.classList.remove('hidden');
                }}}} else {{{{
                    card.classList.add('hidden');
                }}}}
            }}}});
        }}}});
        </script>
    </body>
    </html>
    """

    # Save domain tag index
    with open(tag_index_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Tag index for '{domain}' saved to: {tag_index_file}")


def make_enhanced_subpage_for_tag(domain, tag, items, subpage_name, output_dir, dom_slug):
    """
    Creates an enhanced subpage with better styling and status indicators
    """
    # Remove any None placeholders
    items = [itm for itm in items if itm is not None]
    if not items:
        return  # nothing to render

    subpage_path = os.path.join(output_dir, subpage_name)

    # Create any nested directories required by sanitised domain names with slashes
    os.makedirs(os.path.dirname(subpage_path), exist_ok=True)

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{domain} - {tag}</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f5f5f7;
                color: #1d1d1f;
            }}
            .header {{
                background: white;
                padding: 2rem;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 2rem;
            }}
            .header h1 {{
                margin: 0;
                font-size: 2rem;
                font-weight: 600;
            }}
            .header .breadcrumb {{
                margin-top: 0.5rem;
                color: #6b7280;
            }}
            .header .breadcrumb a {{
                color: #6366f1;
                text-decoration: none;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 2rem 2rem;
            }}
            .findings-grid {{
                display: grid;
                gap: 1.5rem;
            }}
            .finding {{
                background: white;
                border-radius: 12px;
                padding: 1.5rem;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                display: grid;
                grid-template-columns: 300px 1fr;
                gap: 1.5rem;
                align-items: start;
            }}
            .finding img {{
                width: 100%;
                border-radius: 8px;
                border: 1px solid #e5e7eb;
            }}
            .finding-details h3 {{
                margin: 0 0 0.5rem 0;
                font-size: 1.125rem;
                word-break: break-all;
            }}
            .finding-details a {{
                color: #6366f1;
                text-decoration: none;
            }}
            .finding-details a:hover {{
                text-decoration: underline;
            }}
            .metadata {{
                display: flex;
                gap: 1rem;
                margin: 1rem 0;
                flex-wrap: wrap;
            }}
            .metadata-item {{
                background: #f3f4f6;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                font-size: 0.875rem;
            }}
            .metadata-item strong {{
                color: #4b5563;
            }}
            .status-indicator {{
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                font-weight: 500;
                font-size: 0.875rem;
            }}
            .status-indicator.new {{
                background: #d1fae5;
                color: #059669;
            }}
            .status-indicator.changed {{
                background: #fed7aa;
                color: #ea580c;
            }}
            .status-indicator.existing {{
                background: #e0e7ff;
                color: #4338ca;
            }}
            @media (max-width: 768px) {{
                .finding {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="container">
                <h1>{tag}</h1>
                <div class="breadcrumb">
                    <a href="dashboard.html">Dashboard</a> / 
                    <a href="{dom_slug}_tags.html">{domain}</a> / 
                    {tag}
                </div>
            </div>
        </div>
        
        <div class="container">
            <div class="findings-grid">
    """

    # Sort items by status (new first, then changed, then existing)
    status_order = {'new': 0, 'changed': 1, 'existing': 2}
    sorted_items = sorted(items, key=lambda x: (status_order.get(x.get('finding_status', 'existing'), 3), x['url']))

    for f in sorted_items:
        screenshot_html = "N/A"
        if f.get("screenshot") and os.path.exists(f["screenshot"]):
            screenshot_rel = os.path.relpath(f["screenshot"], output_dir)
            screenshot_html = f'<img src="{screenshot_rel}" alt="Screenshot">'

        status = f.get('finding_status', 'unknown')
        status_text = status.capitalize()
        
        html += f"""
                <div class="finding">
                    <div class="screenshot">
                        {screenshot_html}
                    </div>
                    <div class="finding-details">
                        <h3><a href="{f['url']}" target="_blank">{f['url']}</a></h3>
                        <div class="status-indicator {status}">
                            <span>⬤</span> {status_text}
                        </div>
                        <div class="metadata">
                            <div class="metadata-item">
                                <strong>Status:</strong> {f.get('status','')}
                            </div>
                            <div class="metadata-item">
                                <strong>Length:</strong> {f.get('length','')} bytes
                            </div>
                            <div class="metadata-item">
                                <strong>Times Seen:</strong> {f.get('times_seen', 1)}
                            </div>
        
                            <div class="metadata-item">
                                <strong>First Seen:</strong> {f.get('first_seen','')}
                            </div>
            """
        
        if f.get('last_seen') and f.get('finding_status') == 'existing':
            last_seen = f['last_seen']
            if isinstance(last_seen, str) and 'T' in last_seen:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                    last_seen = dt.strftime('%Y-%m-%d %H:%M')
                except:
                    pass
            html += f"""
                            <div class="metadata-item">
                                <strong>Last Seen:</strong> {last_seen}
                            </div>
            """
        
        html += """
                        </div>
                    </div>
                </div>
        """

        # ---- security & technology badges ----
        # Download meta for secrets and file info
        download_meta = f.get('download_meta') or {}

        # Technology & CVEs
        tech_badges, cve_summary = extract_tech_and_cves(f.get('tech') or {})

        # If summary only has _total (no package details) treat as empty for fallback
        if set(cve_summary.keys()) == {"_total"}:
            cve_summary = {}

        # If still empty, fallback to download_meta
        if not cve_summary and download_meta.get('cve_details'):
            for pkg, info in (download_meta.get('cve_details') or {}).items():
                if pkg.lower() in {"null", "none", "_total"}:
                    continue
                if isinstance(info, dict):
                    ids = info.get('ids', [])
                    version = info.get('version','')
                else:
                    ids = info
                    version = ''
                cve_summary[pkg] = {
                    'count': len(ids),
                    'ids': ids,
                    'version': version,
                    'severity': severity_from_count(len(ids))
                }

        tech_badge_html = " ".join(
            f"<span style='background:#6b7280;color:#fff;padding:2px 6px;border-radius:4px;font-size:0.75rem'>{b}</span>" for b in tech_badges
        )

        total_cve_cnt = sum(info['count'] for info in cve_summary.values())
        if not total_cve_cnt:
            tech_dict = f.get('tech') or {}
            total_cve_cnt = tech_dict.get('cve_vulns', 0) or 0
        cve_badge = ""
        if total_cve_cnt:
            sev  = severity_from_count(total_cve_cnt)
            color_map = {'Critical':'#991b1b','High':'#b91c1c','Medium':'#d97706','Low':'#f59e0b'}
            color = color_map.get(sev, '#b91c1c')
            cve_badge = f"<span style='background:{color};color:#fff;padding:2px 6px;border-radius:4px;font-size:0.75rem' title='CVE severity {sev}'>{sev} CVE {total_cve_cnt}</span>"

        # Secrets badge
        secret_cnt = len(download_meta.get('th_secrets', [])) + len(download_meta.get('potential_secrets', []))
        secret_badge = ""
        if secret_cnt:
            secret_badge = f"<span style='background:#be123c;color:#fff;padding:2px 6px;border-radius:4px;font-size:0.75rem' title='Potential secrets detected'>SECRETS {secret_cnt}</span>"

        # Build enhanced secret details HTML with categorization
        secret_details_html = ""
        if secret_cnt:
            from utils.enhanced_reporter import categorize_secret, SECRET_TYPES
            
            secret_by_type = defaultdict(list)
            
            # Categorize TruffleHog secrets
            for s in download_meta.get('th_secrets', []):
                val = s.get('raw') or s.get('redacted') or '***'
                reason = s.get('reason', '')
                secret_info = categorize_secret(val, reason)
                
                # Redact sensitive parts
                if len(val) > 20:
                    redacted = val[:8] + '...' + val[-8:]
                else:
                    redacted = val[:4] + '***'
                    
                secret_by_type[secret_info['type']].append({
                    'value': redacted,
                    'reason': reason,
                    'risk': secret_info['risk'],
                    'icon': secret_info['icon']
                })
            
            # Add potential secrets
            for pat in download_meta.get('potential_secrets', []):
                secret_info = categorize_secret(pat, '')
                if len(pat) > 20:
                    redacted = pat[:8] + '...' + pat[-8:]
                else:
                    redacted = pat[:4] + '***'
                    
                secret_by_type[secret_info['type']].append({
                    'value': redacted,
                    'reason': 'Pattern match',
                    'risk': secret_info['risk'],
                    'icon': secret_info['icon']
                })
            
            if secret_by_type:
                secret_details_html = """
                            <details style='margin-top:0.5rem;font-size:0.8rem'>
                                <summary style='cursor:pointer;'>🔐 Secret Analysis</summary>
                                <div style='margin-top:0.5rem;padding:0.5rem;background:#fef2f2;border-radius:4px'>
                """
                
                # Sort by risk level
                risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
                sorted_types = sorted(secret_by_type.items(), 
                                    key=lambda x: min(risk_order.get(s['risk'], 4) for s in x[1]))
                
                for secret_type, secrets in sorted_types:
                    type_config = SECRET_TYPES.get(secret_type, {'icon': '🔓'})
                    secret_details_html += f"""
                        <div style='margin-bottom:0.5rem'>
                            <strong>{type_config['icon']} {secret_type.replace('_', ' ').title()}</strong>
                    """
                    
                    for secret in secrets:
                        risk_color = {'critical': '#991b1b', 'high': '#dc2626', 'medium': '#f59e0b', 'low': '#3b82f6'}
                        color = risk_color.get(secret['risk'], '#6b7280')
                        secret_details_html += f"""
                            <div style='margin-left:1rem;padding:0.25rem 0'>
                                <code style='background:#fee2e2;padding:2px 4px;border-radius:2px'>{secret['value']}</code>
                                <span style='color:{color};font-size:0.7rem;margin-left:0.5rem'>{secret['risk'].upper()}</span>
                                <em style='color:#6b7280;font-size:0.7rem'> - {secret['reason']}</em>
                            </div>
                        """
                    
                    secret_details_html += "</div>"
                
                secret_details_html += """
                                </div>
                            </details>
                """

        # Enhanced download display
        dl_badge = ""
        download_details = ""
        if f.get('downloadable'):
            file_size = download_meta.get('size', 0)
            file_type = download_meta.get('file_type', 'Unknown')
            mime_type = download_meta.get('mime_type', '')
            
            # Format file size
            if file_size > 1048576:
                size_str = f"{file_size / 1048576:.1f} MB"
            elif file_size > 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            else:
                size_str = f"{file_size} B"
            
            dl_badge = f"""<span style='background:#0369a1;color:#fff;padding:4px 8px;border-radius:4px;font-size:0.75rem'>
                📥 {file_type} ({size_str})
            </span>"""
            
            # Add file details
            if mime_type or file_size > 0:
                sha256 = download_meta.get('sha256', '')
                download_details = f"""
                    <details style='margin-top:0.5rem;font-size:0.8rem'>
                        <summary style='cursor:pointer;'>Download Details</summary>
                        <div style='margin-top:0.5rem;padding:0.5rem;background:#f0f9ff;border-radius:4px'>
                            <strong>File Information:</strong><br>
                            MIME Type: <code>{mime_type or 'Unknown'}</code><br>
                            Size: {size_str}<br>
                            {f'SHA256: <code style="font-size:0.7rem">{sha256[:32]}...</code><br>' if sha256 else ''}
                            <a href="{f['url']}" target="_blank" style="color:#0369a1">Download File →</a>
                        </div>
                    </details>
                """

        if cve_badge or secret_badge or tech_badge_html or dl_badge:
            html += f"""
                            <div class="metadata-item">{dl_badge} {cve_badge} {secret_badge} {tech_badge_html}</div>
            """
        # append secret details if any
        if secret_details_html:
            html += secret_details_html
            
        # append download details if any
        if download_details:
            html += download_details

        # Collapsible CVE details table
        if cve_summary:
            html += """
                            <details style='margin-top:0.5rem;font-size:0.8rem'>
                                <summary style='cursor:pointer;'>CVE Details</summary>
                                <table style='margin-top:0.5rem;border-collapse:collapse'>
                                    <thead><tr><th style='padding:2px 6px;text-align:left'>Package</th><th style='padding:2px 6px'>Version</th><th style='padding:2px 6px'>Count</th><th style='padding:2px 6px'>Severity</th><th style='padding:2px 6px'>IDs</th></tr></thead>
            <tbody>
            """
            for pkg, info in cve_summary.items():
                if pkg.lower() in {"null", "none", "_total"}:
                    continue
                ver = info.get('version','')
                id_links: list[str] = []
                full_ids = info.get('ids', [])
                for _cid in full_ids[:5]:
                    # Build external link (NVD for CVE, GitHub for GHSA, fallback google)
                    if _cid.startswith('CVE'):
                        href = f"https://nvd.nist.gov/vuln/detail/{_cid}"
                    elif _cid.lower().startswith('ghsa'):
                        href = f"https://github.com/advisories/{_cid}"
                    else:
                        href = f"https://www.google.com/search?q={_cid}"

                    desc = _fetch_cve_summary(_cid)
                    if desc:
                        safe_desc = (
                            desc.replace("'", "&#39;").replace('"', "&quot;")[:240]
                        )
                        title_attr = f' title="{safe_desc}"'
                    else:
                        title_attr = ''
                    id_links.append(f"<a href='{href}' target='_blank'{title_attr}>{_cid}</a>")

                extra_cnt = len(full_ids) - 5
                if extra_cnt > 0:
                    id_links.append(f"…+{extra_cnt} more")
                ids_html = ', '.join(id_links)
                tooltip = f"title='{pkg} vulnerabilities'"
                html += f"<tr><td style='padding:2px 6px' {tooltip}>{pkg}</td><td style='padding:2px 6px'>{ver}</td><td style='padding:2px 6px;text-align:center'>{info['count']}</td><td style='padding:2px 6px'>{info['severity']}</td><td style='padding:2px 6px;font-size:0.7rem'>{ids_html}</td></tr>"
            html += """
                                    </tbody></table></details>
            """

    html += f"""
            </div>
            <div style="text-align: center; color: #6b7280; margin-top: 2rem;">
                <a href="{dom_slug}_tags.html" style="color: #6366f1;">← Back to {domain} overview</a>
            </div>
        </div>
    </body>
    </html>
    """

    with open(subpage_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Created enhanced subpage: {subpage_path} for tag={tag}")


def slugify_tag(tag):
    """
    Converts a tag string into a filesystem-safe slug
    """
    return (
        tag.lower()
           .replace(" ", "_")
           .replace("/", "_")
           .replace("\\", "_")
           .replace("(", "")
           .replace(")", "")
           .replace(",", "")
    )


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

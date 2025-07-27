# utils/enhanced_reporter.py
"""Enhanced reporter with better visualizations for security findings"""

import os
import json
import re
import logging
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any, Tuple
from functools import lru_cache
import requests

from utils.tech_helpers import extract_tech_and_cves, aggregate_cves, severity_from_count, get_vuln_severity

# Set up logger
logger = logging.getLogger(__name__)

# Constants
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

# Tech stack logos/icons mapping
TECH_LOGOS = {
    'jquery': '🔷',
    'bootstrap': '🟪',
    'react': '⚛️',
    'vue': '💚',
    'angular': '🔺',
    'wordpress': '🔵',
    'nginx': '🟩',
    'apache': '🪶',
    'php': '🐘',
    'python': '🐍',
    'node': '🟢',
    'mysql': '🐬',
    'postgresql': '🐘',
    'mongodb': '🍃',
    'redis': '🔴',
    'docker': '🐳',
    'kubernetes': '☸️',
    'aws': '☁️',
    'cloudflare': '🌥️'
}

# Secret type categorization
SECRET_TYPES = {
    'api_key': {'pattern': r'api[_-]?key', 'risk': 'high', 'icon': '🔑'},
    'aws_access': {'pattern': r'AKIA[0-9A-Z]{16}', 'risk': 'critical', 'icon': '☁️'},
    'github_token': {'pattern': r'gh[ps]_[a-zA-Z0-9]{36}', 'risk': 'critical', 'icon': '🐙'},
    'private_key': {'pattern': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', 'risk': 'critical', 'icon': '🔐'},
    'password': {'pattern': r'password|passwd|pwd', 'risk': 'high', 'icon': '🔒'},
    'jwt': {'pattern': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'risk': 'medium', 'icon': '🎫'},
    'slack_token': {'pattern': r'xox[baprs]-[0-9a-zA-Z-]+', 'risk': 'high', 'icon': '💬'},
    'database_url': {'pattern': r'(mysql|postgres|mongodb)://[^:]+:[^@]+@', 'risk': 'critical', 'icon': '🗄️'}
}

def categorize_secret(secret_value: str, reason: str = '') -> Dict[str, str]:
    """Categorize a secret by type and assign risk level"""
    secret_lower = secret_value.lower()
    reason_lower = reason.lower()
    
    for secret_type, config in SECRET_TYPES.items():
        if re.search(config['pattern'], secret_lower, re.IGNORECASE) or \
           re.search(config['pattern'], reason_lower, re.IGNORECASE):
            return {
                'type': secret_type,
                'risk': config['risk'],
                'icon': config['icon']
            }
    
    return {'type': 'unknown', 'risk': 'medium', 'icon': '🔓'}

def aggregate_domain_tech(findings: List[Dict]) -> Dict[str, Any]:
    """Aggregate technology stack for a domain"""
    tech_stack = defaultdict(lambda: {'count': 0, 'versions': set(), 'cves': []})
    
    for finding in findings:
        tech_dict = finding.get('tech') or {}
        
        # Skip meta keys
        for tech_name, tech_info in tech_dict.items():
            if tech_name in ['cve_vulns', 'cve_details', 'name', 'version', 'wapp']:
                continue
                
            if isinstance(tech_info, dict):
                version = tech_info.get('version', 'unknown')
                tech_stack[tech_name]['count'] += 1
                if version:
                    tech_stack[tech_name]['versions'].add(version)
                
                # Add CVEs if any
                cve_details = tech_dict.get('cve_details', {})
                if tech_name.lower() in cve_details:
                    tech_stack[tech_name]['cves'].extend(cve_details[tech_name.lower()])
    
    # Convert sets to lists for JSON serialization
    for tech in tech_stack.values():
        tech['versions'] = sorted(list(tech['versions']))
        tech['cves'] = list(set(tech['cves']))  # Remove duplicates
    
    return dict(tech_stack)

def create_enhanced_dashboard(all_domains_data, is_update=False):
    """Create an enhanced dashboard with better visualizations
    
    Parameters:
    - all_domains_data: Dictionary mapping domains to their findings
    - is_update: If True, indicates this is an update to an existing dashboard
    """
    # Import the path manager and findings enricher
    try:
        from utils.path_handler import path_manager
        from utils.findings_enricher import enrich_findings, save_enriched_findings
        
        # Fix domain data before processing
        fixed_data = {}
        for domain, findings in all_domains_data.items():
            logger.info(f"Enriching {len(findings)} findings for {domain}")
            fixed_data[domain] = enrich_findings(domain, findings)
            save_enriched_findings(domain, fixed_data[domain])
        
        # Continue with fixed data
        all_domains_data = fixed_data
    except ImportError:
        logger.warning("path_handler or findings_enricher not available - using raw findings")
    except Exception as e:
        logger.error(f"Error enriching findings for dashboard: {e}")
        
    os.makedirs(HTML_REPORT_DIR, exist_ok=True)
    
    dashboard_file = os.path.join(HTML_REPORT_DIR, "dashboard.html")
    
    # Aggregate statistics
    total_domains = len(all_domains_data)
    total_findings = sum(len(findings) for findings in all_domains_data.values())
    
    # Enhanced aggregation
    global_status_counts = defaultdict(int)
    global_category_counts = defaultdict(int)
    global_secret_types = defaultdict(int)
    global_cve_severity = defaultdict(int)
    domain_data = {}
    
    # Create a set to track all unique vulnerability IDs globally
    global_vuln_ids = set()
    
    # Track severity counts with consistent ordering using a dictionary with predefined keys
    severity_levels = ["Critical", "High", "Medium", "Low"]
    global_cve_severity = {level: 0 for level in severity_levels}
    
    # Process each domain
    for domain, findings in all_domains_data.items():
        domain_tech = aggregate_domain_tech(findings)
        domain_secrets = defaultdict(int)
        domain_downloadable = False
        
        # Use aggregate_cves to get unique CVEs for this domain
        cve_aggregate = aggregate_cves(findings)
        # Store the unique CVEs by package
        domain_cves = {pkg: info["ids"] for pkg, info in cve_aggregate["packages"].items()}
        
        # Add vulnerabilities to global set for deduplication
        for pkg_info in cve_aggregate["packages"].values():
            global_vuln_ids.update(pkg_info["ids"])
            
            # Count severity for each individual vulnerability ID
            for vuln_id in pkg_info["ids"]:
                severity = get_vuln_severity(vuln_id)
                global_cve_severity[severity] += 1
        
        for finding in findings:
            status = finding.get('finding_status', 'unknown')
            global_status_counts[status] += 1
            
            category = finding.get('ai_tag', 'Other')
            global_category_counts[category] += 1
            
            # Check if finding is downloadable
            if finding.get('downloadable'):
                domain_downloadable = True
            
            # Process secrets with categorization
            dm = finding.get('download_meta') or {}
            for secret in dm.get('th_secrets', []):
                secret_info = categorize_secret(
                    secret.get('raw', ''),
                    secret.get('reason', '')
                )
                global_secret_types[secret_info['type']] += 1
                domain_secrets[secret_info['type']] += 1
        
        # Store domain data
        domain_data[domain] = {
            'tech_stack': domain_tech,
            'cve_summary': dict(domain_cves),
            'secret_types': dict(domain_secrets),
            'downloadable': domain_downloadable
        }
    
    # Build enhanced HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>DirHunter AI - Enhanced Security Dashboard</title>
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
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 2rem;
            }}
            .chart-container {{
                background: white;
                padding: 1.5rem;
                border-radius: 12px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                margin-bottom: 2rem;
                height: 400px;
                position: relative;
            }}
            .chart-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                gap: 2rem;
                margin-bottom: 2rem;
            }}
            .risk-card {{
                background: white;
                padding: 1.5rem;
                border-radius: 12px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                border-left: 4px solid #667eea;
            }}
            .tech-badge {{
                display: inline-block;
                padding: 0.25rem 0.75rem;
                margin: 0.25rem;
                border-radius: 20px;
                font-size: 0.875rem;
                background: #f3f4f6;
                color: #374151;
            }}
            .secret-type {{
                display: flex;
                align-items: center;
                padding: 0.5rem;
                margin: 0.25rem 0;
                background: #fef3c7;
                border-radius: 8px;
                font-size: 0.875rem;
            }}
            .cve-severity-critical {{
                background: #fee2e2;
                color: #991b1b;
            }}
            .cve-severity-high {{
                background: #fed7aa;
                color: #c2410c;
            }}
            .cve-severity-medium {{
                background: #fef3c7;
                color: #d97706;
            }}
            .cve-severity-low {{
                background: #dbeafe;
                color: #1e40af;
            }}
            .domain-section {{
                background: white;
                padding: 2rem;
                border-radius: 12px;
                margin-bottom: 2rem;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            }}
            .tech-stack-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
                gap: 1rem;
                margin-top: 1rem;
            }}
            .tech-item {{
                padding: 1rem;
                background: #f9fafb;
                border-radius: 8px;
                border: 1px solid #e5e7eb;
            }}
            .cve-summary {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
                gap: 1rem;
                margin-top: 1rem;
            }}
            .cve-item {{
                padding: 1rem;
                border-radius: 8px;
                border: 1px solid #e5e7eb;
            }}
            .cve-item h4 {{
                margin-top: 0;
                margin-bottom: 0.5rem;
            }}
            .cve-item.cve-severity-critical {{
                background-color: #fee2e2;
                border-left: 4px solid #ef4444;
            }}
            .cve-item.cve-severity-high {{
                background-color: #fed7aa;
                border-left: 4px solid #f97316;
            }}
            .cve-item.cve-severity-medium {{
                background-color: #fef3c7;
                border-left: 4px solid #f59e0b;
            }}
            .cve-item.cve-severity-low {{
                background-color: #dbeafe;
                border-left: 4px solid #3b82f6;
            }}
            .cve-list {{
                margin-top: 0.5rem;
                padding-left: 1.5rem;
            }}
            .cve-list li {{
                margin-bottom: 0.25rem;
            }}
            .cve-list a {{
                color: #4f46e5;
                text-decoration: none;
            }}
            .cve-list a:hover {{
                text-decoration: underline;
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
            /* Remove risk meter styles */
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ DirHunter AI Security Dashboard</h1>
            <p class="subtitle">Enhanced Security Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
        </div>
        
        <div class="container">
            <!-- Overview Cards -->
            <div class="chart-grid">
                <div class="risk-card">
                    <h3>📊 Scan Overview</h3>
                    <p>Total Domains: <strong>{total_domains}</strong></p>
                    <p>Total Findings: <strong>{total_findings}</strong></p>
                    <p>New Findings: <strong style="color: #ef4444">{global_status_counts.get('new', 0)}</strong></p>
                    <p>Changed Findings: <strong style="color: #f59e0b">{global_status_counts.get('changed', 0)}</strong></p>
                </div>
                
                <div class="risk-card">
                    <h3>🔐 Security Summary</h3>
                    <p>Unique Vulnerabilities: <strong>{len(global_vuln_ids)}</strong></p>
                    <p>Total Secrets: <strong>{sum(global_secret_types.values())}</strong></p>
                    <p>Critical Severity: <strong style="color: #ef4444">{global_cve_severity.get('Critical', 0)}</strong></p>
                    <p>High Severity: <strong style="color: #f97316">{global_cve_severity.get('High', 0)}</strong></p>
                    <p>Medium Severity: <strong style="color: #f59e0b">{global_cve_severity.get('Medium', 0)}</strong></p>
                    <p>Low Severity: <strong style="color: #3b82f6">{global_cve_severity.get('Low', 0)}</strong></p>
                </div>
            </div>
            
            <!-- Charts Section -->
            <div class="chart-grid">
                <div class="chart-container">
                    <canvas id="cveChart"></canvas>
                </div>
                <div class="chart-container">
                    <canvas id="secretChart"></canvas>
                </div>
            </div>
            
            <div class="chart-container" style="height: 300px;">
                <canvas id="categoryChart"></canvas>
            </div>
            
            <!-- Search and Filters -->
            <input type="text" class="search-box" id="searchInput" placeholder="Search domains...">
            
            <div class="filter-bar">
                <button class="filter-btn active" data-filter="all">All Domains</button>
                <button class="filter-btn" data-filter="new-findings">New Findings</button>
                <button class="filter-btn" data-filter="with-vulns">With Vulnerabilities</button>
                <button class="filter-btn" data-filter="with-secrets">With Secrets</button>
                <button class="filter-btn" data-filter="with-downloads">With Downloads</button>
            </div>
    """
    
    # Add domain sections with enhanced details
    for domain, domain_info in sorted(domain_data.items(), key=lambda x: x[0]): # Sort by domain name
        # Calculate counts for filtering
        new_findings = sum(1 for f in all_domains_data.get(domain, []) if f.get('finding_status') == 'new')
        
        # Count unique vulnerability IDs
        domain_vuln_ids = set()
        for pkg_ids in domain_info['cve_summary'].values():
            domain_vuln_ids.update(pkg_ids)
        domain_vulns_count = len(domain_vuln_ids)
        
        domain_secrets_count = sum(domain_info['secret_types'].values()) if domain_info['secret_types'] else 0
        
        html += f"""
            <div class="domain-section" 
                 data-domain="{domain}"
                 data-new-findings="{new_findings}"
                 data-vulns="{domain_vulns_count}"
                 data-secrets="{domain_secrets_count}"
                 data-downloadable="{1 if domain_info['downloadable'] else 0}">
                <h2>{domain}</h2>
                
                <h3>🔧 Technology Stack</h3>
                <div class="tech-stack-grid">
        """
        
        for tech_name, tech_info in domain_info['tech_stack'].items():
            icon = TECH_LOGOS.get(tech_name.lower(), '📦')
            versions = ', '.join(tech_info['versions']) if tech_info['versions'] else 'unknown'
            cve_count = len(tech_info['cves'])
            
            cve_badge = ''
            if cve_count > 0:
                severity = severity_from_count(cve_count)
                cve_badge = f'<span class="cve-severity-{severity.lower()}">{cve_count} CVEs</span>'
            
            html += f"""
                <div class="tech-item">
                    <h4>{icon} {tech_name}</h4>
                    <p>Version: {versions}</p>
                    {cve_badge}
                </div>
            """
        
        html += """
                </div>
        """
        
        # Add CVE summary if any
        if domain_info['cve_summary']:
            html += """
                <h3>🩹 CVE Vulnerabilities</h3>
                <div class="cve-summary">
            """
            
            for pkg, cves in domain_info['cve_summary'].items():
                cve_count = len(cves)
                
                # Determine severity based on individual vulnerabilities
                severities = [get_vuln_severity(cve_id) for cve_id in cves]
                # Use the most severe level (Critical > High > Medium > Low)
                severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
                highest_severity = max(severities, key=lambda s: severity_rank.get(s, 0))
                severity_class = highest_severity.lower()
                
                html += f"""
                    <div class="cve-item cve-severity-{severity_class}">
                        <h4>{pkg}</h4>
                        <p>Severity: <strong>{highest_severity}</strong> ({cve_count} vulnerabilities)</p>
                        <ul class="cve-list">
                """
                
                # Sort vulnerabilities by severity (highest first)
                sorted_cves = sorted([(cve_id, get_vuln_severity(cve_id)) for cve_id in cves], 
                                     key=lambda x: severity_rank.get(x[1], 0), 
                                     reverse=True)
                
                # Show first 5 vulnerabilities
                for cve_id, cve_severity in sorted_cves[:5]:
                    severity_color = {
                        "Critical": "#ef4444",
                        "High": "#f97316", 
                        "Medium": "#f59e0b", 
                        "Low": "#3b82f6"
                    }.get(cve_severity, "#6b7280")
                    
                    html += f"""
                            <li>
                                <a href="{'https://nvd.nist.gov/vuln/detail/' if cve_id.startswith('CVE') else 'https://github.com/advisories/'}{cve_id}" target="_blank">
                                    {cve_id}
                                </a>
                                <span style="color: {severity_color}; font-size: 0.8em; margin-left: 5px;">({cve_severity})</span>
                            </li>
                    """
                
                if len(sorted_cves) > 5:
                    html += f"""
                            <li>... and {len(sorted_cves) - 5} more vulnerabilities</li>
                    """
                
                html += """
                        </ul>
                    </div>
                """
            
            html += """
                </div>
            """
        
        # Add secrets summary if any
        if domain_info['secret_types']:
            html += """
                <h3>🔑 Detected Secrets</h3>
                <div>
            """
            for secret_type, count in domain_info['secret_types'].items():
                secret_config = SECRET_TYPES.get(secret_type, {'icon': '🔓', 'risk': 'unknown'})
                html += f"""
                    <div class="secret-type">
                        <span>{secret_config['icon']} {secret_type.replace('_', ' ').title()}: {count}</span>
                        <span style="margin-left: auto; color: {'#ef4444' if secret_config['risk'] == 'critical' else '#f59e0b'}">
                            {secret_config['risk'].upper()}
                        </span>
                    </div>
                """
            html += """
                </div>
            """
        
        # Add downloadable file information if available
        if domain_info['downloadable']:
            html += """
                <h3>📁 Downloadable Files</h3>
                <p>This domain contains downloadable files that were found during the scan.</p>
                <p>Please refer to the detailed findings for specific file locations and content.</p>
            """
        
        html += f"""
                <p style="margin-top: 1rem;">
                    <a href="{_slugify_name(domain)}_tags.html" style="color: #667eea;">View detailed findings →</a>
                </p>
            </div>
        """
    
    # Add JavaScript for charts and filtering
    html += f"""
        </div>
        
        <script>
            // CVE Severity Chart
            const cveCtx = document.getElementById('cveChart').getContext('2d');
            new Chart(cveCtx, {{
                type: 'doughnut',
                data: {{
                    labels: {json.dumps(severity_levels)},
                    datasets: [{{
                        data: {json.dumps([global_cve_severity[level] for level in severity_levels])},
                        backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#3b82f6'],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        title: {{
                            display: true,
                            text: 'CVE Severity Distribution'
                        }}
                    }}
                }}
            }});
            
            // Secret Types Chart
            const secretCtx = document.getElementById('secretChart').getContext('2d');
            new Chart(secretCtx, {{
                type: 'bar',
                data: {{
                    labels: {json.dumps([k.replace('_', ' ').title() for k in global_secret_types.keys()])},
                    datasets: [{{
                        label: 'Count',
                        data: {json.dumps(list(global_secret_types.values()))},
                        backgroundColor: '#667eea'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        title: {{
                            display: true,
                            text: 'Secret Types Found'
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true
                        }}
                    }}
                }}
            }});
            
            // Category Distribution Chart
            const categoryCtx = document.getElementById('categoryChart').getContext('2d');
            new Chart(categoryCtx, {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(list(global_category_counts.keys()))},
                    datasets: [{{
                        label: 'Findings',
                        data: {json.dumps(list(global_category_counts.values()))},
                        backgroundColor: '#764ba2'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {{
                        title: {{
                            display: true,
                            text: 'Finding Categories'
                        }}
                    }}
                }}
            }});
            
            // Domain filtering
            (function() {{
                const searchInput = document.getElementById('searchInput');
                const domainSections = document.querySelectorAll('.domain-section');
                const filterBtns = document.querySelectorAll('.filter-btn');
                
                let currentFilter = 'all';
                
                function applyFilters() {{
                    const searchTerm = searchInput.value.toLowerCase();
                    
                    domainSections.forEach(section => {{
                        const domain = section.dataset.domain.toLowerCase();
                        let show = domain.includes(searchTerm);
                        
                        // Apply category filter
                        if (show && currentFilter !== 'all') {{
                            switch(currentFilter) {{
                                case 'new-findings':
                                    show = parseInt(section.dataset.newFindings) > 0;
                                    break;
                                case 'with-vulns':
                                    show = parseInt(section.dataset.vulns) > 0;
                                    break;
                                case 'with-secrets':
                                    show = parseInt(section.dataset.secrets) > 0;
                                    break;
                                case 'with-downloads':
                                    show = parseInt(section.dataset.downloadable) > 0;
                                    break;
                            }}
                        }}
                        
                        section.style.display = show ? '' : 'none';
                    }});
                }}

                searchInput.addEventListener('input', applyFilters);
                filterBtns.forEach(btn => {{
                    btn.addEventListener('click', () => {{
                        filterBtns.forEach(b => b.classList.remove('active'));
                        btn.classList.add('active');
                        currentFilter = btn.dataset.filter;
                        applyFilters();
                    }});
                }});
            }})();
        </script>
    </body>
    </html>
    """
    
    with open(dashboard_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[+] Enhanced dashboard created: {dashboard_file}")
    return dashboard_file 
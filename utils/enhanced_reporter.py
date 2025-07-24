# utils/enhanced_reporter.py
"""Enhanced reporter with better visualizations for security findings"""

import os
import json
import re
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Any, Tuple
from functools import lru_cache
import requests

from utils.tech_helpers import extract_tech_and_cves, aggregate_cves, severity_from_count

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

def create_enhanced_dashboard(all_domains_data):
    """Create an enhanced dashboard with better visualizations"""
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
    domain_risk_scores = {}
    
    # Process each domain
    for domain, findings in all_domains_data.items():
        domain_tech = aggregate_domain_tech(findings)
        domain_cves = defaultdict(list)
        domain_secrets = defaultdict(int)
        risk_score = 0
        
        for finding in findings:
            status = finding.get('finding_status', 'unknown')
            global_status_counts[status] += 1
            
            category = finding.get('ai_tag', 'Other')
            global_category_counts[category] += 1
            
            # Process secrets with categorization
            dm = finding.get('download_meta') or {}
            for secret in dm.get('th_secrets', []):
                secret_info = categorize_secret(
                    secret.get('raw', ''),
                    secret.get('reason', '')
                )
                global_secret_types[secret_info['type']] += 1
                domain_secrets[secret_info['type']] += 1
                
                # Add to risk score
                risk_multiplier = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}
                risk_score += risk_multiplier.get(secret_info['risk'], 1)
            
            # Process CVEs
            tech_dict = finding.get('tech') or {}
            if tech_dict.get('cve_details'):
                for pkg, cves in tech_dict['cve_details'].items():
                    domain_cves[pkg].extend(cves)
                    
                    # Estimate severity
                    cve_count = len(cves)
                    severity = severity_from_count(cve_count)
                    global_cve_severity[severity] += 1
                    
                    # Add to risk score
                    severity_multiplier = {'Critical': 8, 'High': 4, 'Medium': 2, 'Low': 1}
                    risk_score += severity_multiplier.get(severity, 1) * cve_count
        
        domain_risk_scores[domain] = {
            'score': risk_score,
            'tech_stack': domain_tech,
            'cve_summary': dict(domain_cves),
            'secret_types': dict(domain_secrets)
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
            .risk-meter {{
                height: 20px;
                background: #e5e7eb;
                border-radius: 10px;
                overflow: hidden;
                margin: 1rem 0;
            }}
            .risk-meter-fill {{
                height: 100%;
                background: linear-gradient(90deg, #10b981 0%, #f59e0b 50%, #ef4444 100%);
                transition: width 0.5s ease;
            }}
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
                    <p>Total CVEs: <strong>{sum(global_cve_severity.values())}</strong></p>
                    <p>Total Secrets: <strong>{sum(global_secret_types.values())}</strong></p>
                    <p>Critical Severity: <strong style="color: #ef4444">{global_cve_severity.get('Critical', 0)}</strong></p>
                    <p>High Risk Domains: <strong>{sum(1 for d in domain_risk_scores.values() if d['score'] > 50)}</strong></p>
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
    """
    
    # Add domain sections with enhanced details
    for domain, risk_data in sorted(domain_risk_scores.items(), key=lambda x: -x[1]['score']):
        risk_score = risk_data['score']
        risk_percentage = min(100, risk_score * 2)  # Scale for display
        
        html += f"""
            <div class="domain-section">
                <h2>{domain}</h2>
                <div class="risk-meter">
                    <div class="risk-meter-fill" style="width: {risk_percentage}%"></div>
                </div>
                <p>Risk Score: <strong>{risk_score}</strong></p>
                
                <h3>🔧 Technology Stack</h3>
                <div class="tech-stack-grid">
        """
        
        for tech_name, tech_info in risk_data['tech_stack'].items():
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
        
        # Add secrets summary if any
        if risk_data['secret_types']:
            html += """
                <h3>🔑 Detected Secrets</h3>
                <div>
            """
            for secret_type, count in risk_data['secret_types'].items():
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
        
        html += f"""
                <p style="margin-top: 1rem;">
                    <a href="{_slugify_name(domain)}_tags.html" style="color: #667eea;">View detailed findings →</a>
                </p>
            </div>
        """
    
    # Add JavaScript for charts
    html += f"""
        </div>
        
        <script>
            // CVE Severity Chart
            const cveCtx = document.getElementById('cveChart').getContext('2d');
            new Chart(cveCtx, {{
                type: 'doughnut',
                data: {{
                    labels: {json.dumps(list(global_cve_severity.keys()))},
                    datasets: [{{
                        data: {json.dumps(list(global_cve_severity.values()))},
                        backgroundColor: ['#ef4444', '#f59e0b', '#eab308', '#3b82f6'],
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
        </script>
    </body>
    </html>
    """
    
    with open(dashboard_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"[+] Enhanced dashboard created: {dashboard_file}")
    return dashboard_file 
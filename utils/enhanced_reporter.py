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
from utils.path_handler import PathManager

# Try to import findings_enricher functions
try:
    from utils.findings_enricher import enrich_findings, save_enriched_findings
    FINDINGS_ENRICHER_AVAILABLE = True
except ImportError:
    logger.warning("findings_enricher not available - using raw findings")
    FINDINGS_ENRICHER_AVAILABLE = False
    
    # Define fallbacks if not available
    def enrich_findings(domain, findings, extra=None):
        """Fallback if findings_enricher is not available"""
        return findings
        
    def save_enriched_findings(domain, findings, output_dir=None):
        """Fallback if findings_enricher is not available"""
        pass

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

# First, let's add a function to categorize technologies
def categorize_technology(tech_name: str) -> str:
    """Categorize a technology by its purpose"""
    # Frontend frameworks and libraries
    if tech_name in ('React', 'Vue.js', 'Angular', 'jQuery', 'Bootstrap', 'Next.js', 'Nuxt.js', 'Svelte', 'Ember.js', 'Preact'):
        return 'Frontend'
    
    # Backend frameworks and languages
    elif tech_name in ('Ruby', 'Ruby on Rails', 'Node.js', 'Express', 'Django', 'Flask', 'Laravel', 'Spring', 'ASP.NET', 'PHP'):
        return 'Backend'
    
    # Databases
    elif tech_name in ('MySQL', 'PostgreSQL', 'MongoDB', 'SQLite', 'Redis', 'Elasticsearch', 'Cassandra', 'DynamoDB'):
        return 'Database'
    
    # Cloud services
    elif tech_name in ('AWS', 'Azure', 'Google Cloud Platform', 'Firebase', 'Netlify', 'Vercel', 'Heroku', 'AWS EC2', 'AWS Lambda', 'Amazon S3'):
        return 'Cloud'
    
    # CDN and caching
    elif tech_name in ('Cloudflare', 'Akamai', 'Fastly', 'CloudFront', 'Varnish', 'Nginx'):
        return 'CDN/Cache'
    
    # Analytics and marketing
    elif tech_name in ('Google Analytics', 'Google Tag Manager', 'Facebook Pixel', 'Hotjar', 'Mixpanel', 'Segment', 'Intercom', 'Mailchimp', 'HubSpot'):
        return 'Analytics'
    
    # CMS
    elif tech_name in ('WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify', 'Wix', 'Squarespace', 'Ghost'):
        return 'CMS'
    
    # Security features
    elif tech_name in ('HSTS', 'Content-Security-Policy', 'Feature-Policy', 'ModSecurity', 'TrustArc'):
        return 'Security'
    
    # Default catch-all
    return 'Other'

def create_enhanced_dashboard(all_findings, results_dir=None, is_update=False):
    """
    Create an enhanced HTML dashboard with visualizations and metrics
    
    Parameters:
    - all_findings: Dictionary mapping domains to their findings
    - results_dir: Directory to save the dashboard
    - is_update: If True, indicates this is an update to an existing dashboard
    """
    try:
        # Set default output directory if not provided
        if not results_dir:
            results_dir = HTML_REPORT_DIR
        
        # Ensure output directory exists
        os.makedirs(results_dir, exist_ok=True)
        
        # Define paths
        dashboard_path = os.path.join(results_dir, "enhanced_dashboard.html")
        
        # If findings is empty, use domains instead
        domains = all_findings
        if not all_findings:
            logger.warning("No findings data provided for enhanced dashboard")
            return None
            
        # Try to enrich findings with extra data
        try:
            # Try to import findings enricher (non-essential)
            # This is optional and we'll continue if it's not available
            try:
                from utils.findings_enricher import enrich_findings, save_enriched_findings
                
                # Enrich the findings data
                for domain in list(domains.keys()):
                    try:
                        # Call with only the expected arguments
                        domains[domain] = enrich_findings(domain, domains[domain])
                    except Exception as e:
                        logger.warning(f"Failed to enrich findings for {domain}: {e}")
                        
                # Save enriched data
                try:
                    for domain, findings in domains.items():
                        save_enriched_findings(domain, findings)
                except Exception as e:
                    logger.warning(f"Failed to save enriched findings: {e}")
            except ImportError:
                # Define fallback functions if module not available
                logger.debug("Findings enricher module not available")
                
                # These are placeholder functions that just return the original data
                def enrich_findings(domain, findings):
                    return findings
                    
                def save_enriched_findings(domain, findings, output_dir=None):
                    pass
        except Exception as e:
            logger.warning(f"Error during findings enrichment: {e}")
        
        # Calculate dashboard statistics
        # ---------------------------------
        # Count total domains and endpoints
        total_domains = len(domains)
        total_endpoints = sum(len(findings) for findings in domains.values())
        
        # Count by status
        finding_stats = Counter()
        for domain_findings in domains.values():
            for finding in domain_findings:
                status = finding.get("finding_status", "unknown")
                finding_stats[status] += 1
        
        # Count vulnerabilities
        vuln_stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        for domain_findings in domains.values():
            for finding in domain_findings:
                tech = finding.get("tech", {})
                if tech and "cve_details" in tech:
                    for pkg, details in tech["cve_details"].items():
                        if isinstance(details, dict) and "ids" in details:
                            severity = details.get("severity", "").lower()
                            vuln_count = len(details["ids"])
                            vuln_stats["total"] += vuln_count
                            
                            if "critical" in severity:
                                vuln_stats["critical"] += vuln_count
                            elif "high" in severity:
                                vuln_stats["high"] += vuln_count
                            elif "medium" in severity:
                                vuln_stats["medium"] += vuln_count
                            else:
                                vuln_stats["low"] += vuln_count
        
        # Count secrets
        secret_stats = {"total": 0}
        for domain_findings in domains.values():
            for finding in domain_findings:
                secrets = finding.get("secrets", [])
                if secrets:
                    secret_stats["total"] += len(secrets)
        
        # Count and categorize technologies
        tech_counter = Counter()
        tech_categories = Counter()
        
        # Tech logo mapping for chart display
        TECH_LOGOS = {
            "jQuery": "jquery.png",
            "Bootstrap": "bootstrap.png",
            "React": "react.png",
            "Angular": "angular.png",
            "WordPress": "wordpress.png",
            "Nginx": "nginx.png",
            "Apache": "apache.png",
            "PHP": "php.png",
            "Node.js": "nodejs.png"
            # Add more as needed
        }
        
        for domain_findings in domains.values():
            for finding in domain_findings:
                tech = finding.get("tech", {})
                if tech:
                    for tech_name in tech.keys():
                        # Skip metadata keys
                        if tech_name not in ["cve_vulns", "cve_details"]:
                            tech_counter[tech_name] += 1
                            
                            # Categorize technology
                            if any(x in tech_name.lower() for x in ["jquery", "bootstrap", "react", "angular", "css"]):
                                tech_categories["Frontend"] += 1
                            elif any(x in tech_name.lower() for x in ["php", "node", "django", "flask", "rails"]):
                                tech_categories["Backend"] += 1
                            elif any(x in tech_name.lower() for x in ["mysql", "postgres", "mongodb", "sql"]):
                                tech_categories["Database"] += 1
                            elif any(x in tech_name.lower() for x in ["aws", "azure", "cloudflare", "cdn"]):
                                tech_categories["Cloud/CDN"] += 1
                            elif any(x in tech_name.lower() for x in ["wordpress", "drupal", "joomla", "magento"]):
                                tech_categories["CMS"] += 1
                            elif any(x in tech_name.lower() for x in ["analytics", "google tag", "matomo"]):
                                tech_categories["Analytics"] += 1
                            else:
                                tech_categories["Other"] += 1
        
        tech_stats = {
            "total": sum(tech_counter.values()),
            "unique": len(tech_counter),
            "top": tech_counter.most_common(10),
            "categories": {k: v for k, v in tech_categories.most_common()}
        }
        
        # Create the enhanced dashboard
        with open(dashboard_path, 'w') as f:
            f.write(f"""<!DOCTYPE html>
<html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Security Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding-top: 20px;
        }}
        .header-section {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .stat-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0,0,0,0.1);
        }}
        .stat-value {{
                font-size: 2.5rem;
            font-weight: bold;
            color: #4a6cf7;
        }}
        .stat-label {{
            color: #666;
            font-size: 1rem;
            margin-top: 5px;
            }}
            .chart-container {{
                background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .finding-status-new {{
            color: #28a745;
        }}
        .finding-status-changed {{
            color: #fd7e14;
        }}
        .finding-status-existing {{
            color: #6c757d;
        }}
        .technology-tag {{
                display: inline-block;
            background: #e9ecef;
            color: #495057;
            padding: 4px 10px;
                border-radius: 20px;
            margin: 3px;
            font-size: 0.85rem;
        }}
        .vulnerability-critical {{
            background: #dc3545;
            color: white;
        }}
        .vulnerability-high {{
            background: #fd7e14;
            color: white;
        }}
        .vulnerability-medium {{
            background: #ffc107;
            color: #212529;
        }}
        .vulnerability-low {{
            background: #6c757d;
                color: white;
            }}
        .table-responsive {{
            overflow-x: auto;
        }}
        </style>
    </head>
    <body>
    <div class="container">
        <!-- Header Section -->
        <div class="row">
            <div class="col-12 header-section">
                <h1><i class="fas fa-shield-alt"></i> Enhanced Security Dashboard</h1>
                <p>Comprehensive overview of security findings, vulnerabilities and technologies</p>
            </div>
        </div>
        
        <!-- Summary Statistics -->
        <div class="row">
            <div class="col-md-3">
                <div class="stat-card text-center">
                    <div class="stat-value">{total_domains}</div>
                    <div class="stat-label">Domains Scanned</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card text-center">
                    <div class="stat-value">{total_endpoints}</div>
                    <div class="stat-label">Total Endpoints</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card text-center">
                    <div class="stat-value finding-status-new">{finding_stats.get('new', 0)}</div>
                    <div class="stat-label">New Findings</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card text-center">
                    <div class="stat-value">{vuln_stats['total']}</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
                </div>
            </div>
            
        <!-- Technology Charts -->
        <div class="row">
            <div class="col-md-6">
                <div class="chart-container">
                    <h3>Top Technologies</h3>
                    <canvas id="techChart"></canvas>
                </div>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <h3>Technology Distribution</h3>
                    <canvas id="techCategoryChart"></canvas>
                </div>
            </div>
            </div>
        
        <!-- Vulnerability Breakdown -->
        <div class="row">
            <div class="col-md-12">
                <div class="chart-container">
                    <h3>Vulnerability Severity Breakdown</h3>
                    <div class="row align-items-center">
                        <div class="col-md-6">
                            <canvas id="vulnChart"></canvas>
                        </div>
                        <div class="col-md-6">
                            <div class="table-responsive">
                                <table class="table table-bordered">
                                    <thead>
                                        <tr>
                                            <th>Severity</th>
                                            <th>Count</th>
                                            <th>Percentage</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr class="table-danger">
                                            <td>Critical</td>
                                            <td>{vuln_stats['critical']}</td>
                                            <td>{round(vuln_stats['critical'] / max(vuln_stats['total'], 1) * 100, 1)}%</td>
                                        </tr>
                                        <tr class="table-warning">
                                            <td>High</td>
                                            <td>{vuln_stats['high']}</td>
                                            <td>{round(vuln_stats['high'] / max(vuln_stats['total'], 1) * 100, 1)}%</td>
                                        </tr>
                                        <tr class="table-info">
                                            <td>Medium</td>
                                            <td>{vuln_stats['medium']}</td>
                                            <td>{round(vuln_stats['medium'] / max(vuln_stats['total'], 1) * 100, 1)}%</td>
                                        </tr>
                                        <tr class="table-secondary">
                                            <td>Low</td>
                                            <td>{vuln_stats['low']}</td>
                                            <td>{round(vuln_stats['low'] / max(vuln_stats['total'], 1) * 100, 1)}%</td>
                                        </tr>
                                    </tbody>
                                </table>
                </div>
                </div>
                    </div>
                </div>
                    </div>
                </div>
        
        <!-- Links to other dashboards -->
        <div class="row mb-4">
            <div class="col-12 text-center">
                <a href="../html/dashboard.html" class="btn btn-primary btn-lg">View Detailed Dashboard</a>
                <a href="../html/summary.html" class="btn btn-outline-secondary btn-lg ms-3">View Summary Report</a>
            </div>
        </div>
        
        <footer class="text-center text-muted mt-5">
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
        </div>
        
        <script>
        document.addEventListener('DOMContentLoaded', function() {{
            // Top Technologies Chart
            const techCtx = document.getElementById('techChart').getContext('2d');
            new Chart(techCtx, {{
                type: 'bar',
                data: {{
                    labels: {json.dumps([name for name, _ in tech_stats['top']])},
                    datasets: [{{
                        label: 'Occurrence Count',
                        data: {json.dumps([count for _, count in tech_stats['top']])},
                        backgroundColor: 'rgba(75, 192, 192, 0.6)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    indexAxis: 'y',
                    scales: {{
                        x: {{
                            beginAtZero: true
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            display: false
                        }}
                    }}
                }}
            }});
            
            // Technology Categories Chart
            const categoryCtx = document.getElementById('techCategoryChart').getContext('2d');
            new Chart(categoryCtx, {{
                type: 'pie',
                data: {{
                    labels: {json.dumps(list(tech_stats['categories'].keys()))},
                    datasets: [{{
                        data: {json.dumps(list(tech_stats['categories'].values()))},
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.7)',
                            'rgba(54, 162, 235, 0.7)',
                            'rgba(255, 206, 86, 0.7)',
                            'rgba(75, 192, 192, 0.7)',
                            'rgba(153, 102, 255, 0.7)',
                            'rgba(255, 159, 64, 0.7)',
                            'rgba(199, 199, 199, 0.7)'
                        ],
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    plugins: {{
                        legend: {{
                            position: 'right'
                        }}
                    }}
                }}
            }});
            
            // Vulnerability Severity Chart
            const vulnCtx = document.getElementById('vulnChart').getContext('2d');
            new Chart(vulnCtx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low'],
                    datasets: [{{
                        data: [
                            {vuln_stats['critical']}, 
                            {vuln_stats['high']}, 
                            {vuln_stats['medium']}, 
                            {vuln_stats['low']}
                        ],
                        backgroundColor: [
                            'rgba(220, 53, 69, 0.8)',
                            'rgba(253, 126, 20, 0.8)',
                            'rgba(255, 193, 7, 0.8)',
                            'rgba(108, 117, 125, 0.8)'
                        ],
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    plugins: {{
                        legend: {{
                            position: 'right'
                        }}
                    }}
                }}
                    }});
                }});
        </script>
    </body>
</html>""")
        
        logger.info(f"Enhanced dashboard created: {dashboard_path}")
        return dashboard_path
        
    except Exception as e:
        logger.error(f"Failed to create enhanced dashboard: {e}")
        
        # Try to create a basic dashboard as fallback
        try:
            fallback_path = os.path.join(results_dir, "raw_dashboard.html")
            with open(fallback_path, 'w') as f:
                f.write(f"""<!DOCTYPE html>
<html>
<head><title>Basic Dashboard</title></head>
<body>
    <h1>Basic Dashboard (Enhanced dashboard creation failed)</h1>
    <p>Error: {str(e)}</p>
    <p>Domains scanned: {len(all_findings)}</p>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <a href="../html/dashboard.html">View Standard Dashboard</a>
</body>
</html>""")
            logger.warning(f"Falling back to raw findings dashboard.")
            return fallback_path
        except Exception as fallback_error:
            logger.warning(f"Basic dashboard creation failed: {fallback_error}")
            return None 
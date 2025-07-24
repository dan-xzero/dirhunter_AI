# utils/enhanced_slack.py
"""Enhanced Slack alerts with rich formatting and better visualization"""

import os
import requests
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any

from utils.tech_helpers import aggregate_cves, severity_from_count
from utils.enhanced_reporter import categorize_secret, SECRET_TYPES, TECH_LOGOS

REPORT_BASE_URL = os.getenv("REPORT_BASE_URL", "https://your-domain.com")

def create_risk_meter(score: int, max_score: int = 100) -> str:
    """Create a visual risk meter using Unicode blocks"""
    percentage = min(100, (score / max_score) * 100)
    filled = int(percentage / 10)
    meter = "🟩" * max(0, 3 - filled) + "🟨" * min(3, max(0, filled - 3)) + "🟥" * max(0, filled - 6)
    empty = "⬜" * (10 - filled)
    return meter + empty

def send_enhanced_slack_alert(webhook_url: str, all_domains_data: Dict[str, List[Dict]]) -> bool:
    """Send an enhanced Slack alert with rich formatting"""
    
    if not webhook_url:
        print("[!] No Slack webhook URL provided")
        return False
    
    # Aggregate data
    total_domains = len(all_domains_data)
    total_findings = sum(len(findings) for findings in all_domains_data.values())
    
    # Enhanced statistics
    global_stats = {
        'status_counts': defaultdict(int),
        'category_counts': defaultdict(int),
        'secret_types': defaultdict(int),
        'cve_severity': defaultdict(int),
        'tech_stack': defaultdict(lambda: {'count': 0, 'domains': set()}),
        'critical_findings': [],
        'domains_with_secrets': [],
        'domains_with_cves': []
    }
    
    # Process each domain
    domain_summaries = {}
    for domain, findings in all_domains_data.items():
        domain_stats = {
            'new': 0, 'changed': 0, 'existing': 0,
            'secrets': defaultdict(int),
            'cves': defaultdict(list),
            'tech': defaultdict(set),
            'risk_score': 0
        }
        
        for finding in findings:
            # Status
            status = finding.get('finding_status', 'unknown')
            global_stats['status_counts'][status] += 1
            domain_stats[status] += 1
            
            # Category
            category = finding.get('ai_tag', 'Other')
            global_stats['category_counts'][category] += 1
            
            # Secrets
            dm = finding.get('download_meta') or {}
            for secret in dm.get('th_secrets', []):
                secret_info = categorize_secret(secret.get('raw', ''), secret.get('reason', ''))
                global_stats['secret_types'][secret_info['type']] += 1
                domain_stats['secrets'][secret_info['type']] += 1
                
                # Risk scoring
                risk_multiplier = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1}
                domain_stats['risk_score'] += risk_multiplier.get(secret_info['risk'], 1)
            
            # Technology
            tech_dict = finding.get('tech') or {}
            for tech_name, tech_info in tech_dict.items():
                if tech_name not in ['cve_vulns', 'cve_details', 'name', 'version', 'wapp']:
                    global_stats['tech_stack'][tech_name]['count'] += 1
                    global_stats['tech_stack'][tech_name]['domains'].add(domain)
                    if isinstance(tech_info, dict) and tech_info.get('version'):
                        domain_stats['tech'][tech_name].add(tech_info['version'])
            
            # CVEs
            if tech_dict.get('cve_details'):
                for pkg, cves in tech_dict['cve_details'].items():
                    domain_stats['cves'][pkg].extend(cves)
                    cve_count = len(cves)
                    severity = severity_from_count(cve_count)
                    global_stats['cve_severity'][severity] += cve_count
                    domain_stats['risk_score'] += {'Critical': 8, 'High': 4, 'Medium': 2, 'Low': 1}.get(severity, 1) * cve_count
            
            # Critical findings
            from utils.ai_analyzer import get_category_priority
            priority = get_category_priority(category)
            if priority >= 9 and status in ['new', 'changed']:
                global_stats['critical_findings'].append({
                    'domain': domain,
                    'url': finding['url'],
                    'category': category,
                    'status': status
                })
        
        domain_summaries[domain] = domain_stats
        
        if sum(domain_stats['secrets'].values()) > 0:
            global_stats['domains_with_secrets'].append(domain)
        if sum(len(cves) for cves in domain_stats['cves'].values()) > 0:
            global_stats['domains_with_cves'].append(domain)
    
    # Build Slack blocks
    blocks = []
    
    # Header with gradient effect (simulated)
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": "🛡️ DirHunter AI Security Report",
            "emoji": True
        }
    })
    
    # Risk overview section
    total_risk = sum(d['risk_score'] for d in domain_summaries.values())
    risk_meter = create_risk_meter(total_risk, total_domains * 100)
    
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*Overall Security Risk*\n{risk_meter}\nRisk Score: `{total_risk}`"
        },
        "fields": [
            {"type": "mrkdwn", "text": f"*🌐 Domains*\n`{total_domains}`"},
            {"type": "mrkdwn", "text": f"*📍 Findings*\n`{total_findings}`"},
            {"type": "mrkdwn", "text": f"*🆕 New*\n`{global_stats['status_counts']['new']}`"},
            {"type": "mrkdwn", "text": f"*🔄 Changed*\n`{global_stats['status_counts']['changed']}`"}
        ]
    })
    
    # Critical alerts
    if global_stats['critical_findings']:
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🚨 Critical Security Alerts* ({len(global_stats['critical_findings'])} findings)"
            }
        })
        
        for finding in global_stats['critical_findings'][:3]:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"• *{finding['domain']}*\n  {finding['category']} - {finding['status'].upper()}\n  `{finding['url']}`"
                }
            })
    
    # Secret analysis
    if global_stats['secret_types']:
        blocks.append({"type": "divider"})
        
        secret_summary = []
        for secret_type, count in sorted(global_stats['secret_types'].items(), key=lambda x: -x[1]):
            config = SECRET_TYPES.get(secret_type, {'icon': '🔓', 'risk': 'unknown'})
            risk_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(config['risk'], '⚪')
            secret_summary.append(f"{config['icon']} {secret_type.replace('_', ' ').title()}: `{count}` {risk_emoji}")
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🔐 Detected Secrets* ({sum(global_stats['secret_types'].values())} total)\n" + "\n".join(secret_summary[:5])
            }
        })
        
        if global_stats['domains_with_secrets']:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": f"Affected domains: {', '.join(global_stats['domains_with_secrets'][:5])}"
                }]
            })
    
    # CVE summary with visualization
    if global_stats['cve_severity']:
        blocks.append({"type": "divider"})
        
        cve_total = sum(global_stats['cve_severity'].values())
        severity_text = []
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            if sev in global_stats['cve_severity']:
                count = global_stats['cve_severity'][sev]
                emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}[sev]
                bar_length = int((count / cve_total) * 10)
                bar = "▓" * bar_length + "░" * (10 - bar_length)
                severity_text.append(f"{emoji} {sev}: `{count}` {bar}")
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🩹 CVE Analysis* ({cve_total} vulnerabilities)\n" + "\n".join(severity_text)
            }
        })
    
    # Technology stack overview
    if global_stats['tech_stack']:
        blocks.append({"type": "divider"})
        
        # Sort by prevalence
        top_tech = sorted(global_stats['tech_stack'].items(), key=lambda x: -x[1]['count'])[:8]
        tech_grid = []
        
        for tech_name, info in top_tech:
            icon = TECH_LOGOS.get(tech_name.lower(), '📦')
            tech_grid.append(f"{icon} *{tech_name}*\n`{info['count']}` instances\n`{len(info['domains'])}` domains")
        
        # Create 2x4 grid
        for i in range(0, len(tech_grid), 2):
            fields = [{"type": "mrkdwn", "text": tech_grid[i]}]
            if i + 1 < len(tech_grid):
                fields.append({"type": "mrkdwn", "text": tech_grid[i + 1]})
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*🔧 Technology Stack*" if i == 0 else " "
                },
                "fields": fields
            })
    
    # Domain details (compact)
    blocks.append({"type": "divider"})
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "*📊 Domain Summary*"
        }
    })
    
    for domain, stats in sorted(domain_summaries.items(), key=lambda x: -x[1]['risk_score'])[:5]:
        risk_meter_mini = create_risk_meter(stats['risk_score'], 100)[:5]
        
        summary_parts = [f"*{domain}* {risk_meter_mini}"]
        if stats['new'] > 0:
            summary_parts.append(f"🆕 {stats['new']}")
        if stats['changed'] > 0:
            summary_parts.append(f"🔄 {stats['changed']}")
        if sum(stats['secrets'].values()) > 0:
            summary_parts.append(f"🔑 {sum(stats['secrets'].values())}")
        if sum(len(cves) for cves in stats['cves'].values()) > 0:
            summary_parts.append(f"🩹 {sum(len(cves) for cves in stats['cves'].values())}")
        
        report_link = f"{REPORT_BASE_URL}/reports/{domain.replace('://', '_').replace('/', '_')}_tags.html"
        summary_parts.append(f"<{report_link}|View Report>")
        
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": " | ".join(summary_parts)
            }]
        })
    
    # Call to action
    blocks.append({"type": "divider"})
    
    dashboard_url = f"{REPORT_BASE_URL}/reports/dashboard.html"
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "*🎯 Next Steps*\n• Review critical findings immediately\n• Check domains with detected secrets\n• Update vulnerable components"
        },
        "accessory": {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "📊 Full Dashboard",
                "emoji": True
            },
            "url": dashboard_url,
            "style": "primary"
        }
    })
    
    # Footer
    blocks.append({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": f"_Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} | DirHunter AI v2.0_"
        }]
    })
    
    # Send to Slack
    payload = {
        "text": f"Security scan complete: {total_domains} domains, {total_findings} findings",
        "blocks": blocks[:50],  # Slack limit
        "unfurl_links": False,
        "unfurl_media": False
    }
    
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 200:
            print("[+] Enhanced Slack alert sent successfully")
            return True
        else:
            print(f"[!] Slack alert failed: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"[!] Error sending Slack alert: {e}")
        return False 
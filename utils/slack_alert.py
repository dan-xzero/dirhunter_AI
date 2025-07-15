import requests
import os
from dotenv import load_dotenv
from collections import defaultdict
from datetime import datetime
from utils.tech_helpers import aggregate_cves, severity_from_count

load_dotenv(override=True)
REPORT_BASE_URL = os.getenv("REPORT_BASE_URL")

def send_consolidated_slack_alert(all_results, webhook_url):
    """
    Send a single consolidated Slack message for all domains with enhanced formatting
    """
    if not all_results:
        return
    
    # Aggregate statistics
    total_domains = len(all_results)
    total_findings = sum(len(findings) for findings in all_results.values())
    # ----------------------------------------------------------------
    # CVE aggregation across all findings
    # ----------------------------------------------------------------
    all_findings_flat = [f for findings in all_results.values() for f in findings if f]
    global_cve_summary = aggregate_cves(all_findings_flat)
    total_cves = global_cve_summary["total"]
    
    # Count by status and category
    status_counts = defaultdict(int)
    category_counts = defaultdict(int)
    high_priority_findings = []
    domain_stats = {}
    
    for domain, findings in all_results.items():
        domain_new = domain_changed = domain_existing = 0
        domain_secrets = 0
        domain_cves    = 0
        
        secret_urls = []
        for finding in findings:
            # Count by status
            status = finding.get('finding_status', 'unknown')
            status_counts[status] += 1
            
            if status == 'new':
                domain_new += 1
            elif status == 'changed':
                domain_changed += 1
            else:
                domain_existing += 1
            
            # Count by category
            category = finding.get('ai_tag', 'Other')
            category_counts[category] += 1
            
            # Secrets via trufflehog
            secrets = finding.get('download_meta', {}).get('th_secrets', []) if finding.get('download_meta') else []
            if secrets:
                domain_secrets += len(secrets)
                secret_urls.append(finding['url'])

            # Collect high priority findings
            from utils.ai_analyzer import get_category_priority
            priority = get_category_priority(category)
            if priority >= 7:
                high_priority_findings.append({
                    'domain': domain,
                    'url': finding['url'],
                    'category': category,
                    'status': status,
                    'priority': priority
                })
        
        # CVE summary per domain
        domain_cves = aggregate_cves(findings)["total"] if findings else 0
        domain_stats[domain] = {
            'total': len(findings),
            'new': domain_new,
            'changed': domain_changed,
            'existing': domain_existing,
            'secrets': domain_secrets,
            'cves': domain_cves,
            'secret_urls': secret_urls
        }
    
    # Sort high priority findings
    high_priority_findings.sort(key=lambda x: (-x['priority'], x['domain'], x['url']))
    
    # Build the message blocks
    blocks = []
    
    # Header with timestamp
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"🔍 Security Scan Complete - {datetime.now().strftime('%b %d, %Y at %H:%M')}",
            "emoji": True
        }
    })
    
    # Summary section with better formatting
    summary_lines = []
    
    # Overall stats
    summary_lines.append(f"*📊 Overall Statistics*")
    summary_lines.append(f"• Domains scanned: `{total_domains}`")
    summary_lines.append(f"• Total findings: `{total_findings}`")
    if total_cves:
        summary_lines.append(f"• Total CVEs: `{total_cves}`")
    
    # Status breakdown with visual indicators
    if status_counts.get('new', 0) > 0 or status_counts.get('changed', 0) > 0:
        summary_lines.append("")
        summary_lines.append("*🚨 Attention Required*")
        if status_counts.get('new', 0) > 0:
            summary_lines.append(f"• 🆕 New findings: `{status_counts.get('new', 0)}`")
        if status_counts.get('changed', 0) > 0:
            summary_lines.append(f"• 🔄 Changed findings: `{status_counts.get('changed', 0)}`")
        if status_counts.get('existing', 0) > 0:
            summary_lines.append(f"• ✅ Existing findings: `{status_counts.get('existing', 0)}`")
    
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "\n".join(summary_lines)
        }
    })
    
    # Add divider
    blocks.append({"type": "divider"})
    
    # High priority findings section (if any)
    if high_priority_findings:
        critical_findings = [f for f in high_priority_findings if f['priority'] >= 9]
        high_findings = [f for f in high_priority_findings if 7 <= f['priority'] < 9]
        
        priority_text = "*🔥 High Priority Security Findings*\n\n"
        
        # Show critical findings first
        if critical_findings:
            priority_text += "*🔴 CRITICAL:*\n"
            for f in critical_findings[:5]:  # Limit to top 5
                status_icon = "🆕" if f['status'] == 'new' else "🔄" if f['status'] == 'changed' else ""
                priority_text += f"• {status_icon} `{f['domain']}` - [{f['category']}]\n  └─ `{f['url']}`\n"
            if len(critical_findings) > 5:
                priority_text += f"  _...and {len(critical_findings) - 5} more critical findings_\n"
            priority_text += "\n"
        
        # Show high priority findings
        if high_findings:
            priority_text += "*🟠 HIGH:*\n"
            for f in high_findings[:5]:  # Limit to top 5
                status_icon = "🆕" if f['status'] == 'new' else "🔄" if f['status'] == 'changed' else ""
                priority_text += f"• {status_icon} `{f['domain']}` - [{f['category']}]\n  └─ `{f['url']}`\n"
            if len(high_findings) > 5:
                priority_text += f"  _...and {len(high_findings) - 5} more high priority findings_\n"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": priority_text[:3000]  # Slack limit
            }
        })
        
        blocks.append({"type": "divider"})
    
    # Category distribution - show top categories
    if category_counts:
        sorted_categories = sorted(category_counts.items(), key=lambda x: -x[1])[:5]
        category_text = "*📈 Top Finding Categories*\n"
        for category, count in sorted_categories:
            # Create a simple bar chart
            bar_length = int((count / total_findings) * 20)
            bar = "█" * bar_length + "░" * (20 - bar_length)
            percentage = (count / total_findings) * 100
            category_text += f"`{category:<20}` {bar} {count} ({percentage:.0f}%)\n"
        
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": category_text
            }
        })
        
        blocks.append({"type": "divider"})
    
    # Domain breakdown with emojis
    domain_text = "*🌐 Domain Breakdown*\n"
    for domain in sorted(domain_stats.keys()):
        stats = domain_stats[domain]
        domain_text += f"\n*`{domain}`*\n"
        
        # Show stats with visual indicators
        if stats['new'] > 0 or stats['changed'] > 0:
            domain_text += f"  🔔 "
            if stats['new'] > 0:
                domain_text += f"New: {stats['new']} "
            if stats['changed'] > 0:
                domain_text += f"Changed: {stats['changed']} "
            if stats['existing'] > 0:
                domain_text += f"Existing: {stats['existing']}"
            domain_text += "\n"
        else:
            domain_text += f"  ✅ All findings are existing ({stats['existing']})\n"

        if stats.get('secrets'):
            domain_text += f"  🔑 Secrets detected: {stats['secrets']}\n"
            # Show up to 3 URLs with secrets
            for u in stats.get('secret_urls', [])[:3]:
                domain_text += f"     • <{u}|download>\n"
            if len(stats.get('secret_urls', [])) > 3:
                domain_text += f"     _...and {len(stats['secret_urls'])-3} more_\n"
        
        if stats.get('cves'):
            sev = severity_from_count(stats['cves'])
            emoji_map = {'Critical':'🔴','High':'🟠','Medium':'🟡','Low':'🟢'}
            icon = emoji_map.get(sev,'⚠️')
            domain_text += f"  {icon} CVEs: {stats['cves']} ({sev})\n"
        
        # Add report link
        report_link = f"{REPORT_BASE_URL}/reports/{domain}_tags.html"
        domain_text += f"  📄 <{report_link}|View Detailed Report>\n"
    
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": domain_text[:3000]  # Slack limit
        }
    })
    # ---------------- Top vulnerable packages section ----------------
    if global_cve_summary["packages"]:
        packages_sorted = [it for it in sorted(global_cve_summary["packages"].items(), key=lambda x: -x[1]["count"]) if it[0].lower() not in {"null", "none"}][:5]
        vuln_text = "*🩹 Top Vulnerable Packages*\n"
        for pkg, info in packages_sorted:
            sev = info.get('severity')
            count = info.get('count')
            ver = info.get('version', '')
            icon = {'Critical':'🔴','High':'🟠','Medium':'🟡','Low':'🟢'}.get(sev,'⚠️')
            pkg_label = f"{pkg}@{ver}" if ver else pkg
            ids_preview = ', '.join(info.get('ids', [])[:3])
            vuln_text += f"• {icon} `{pkg_label}` – {count} CVEs ({sev}) [{ids_preview}]\n"

        blocks.append({
            "type": "divider"
        })

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": vuln_text[:3000]}
        })
    
    # Dashboard link with call-to-action
    blocks.append({"type": "divider"})
    
    dashboard_url = f"{REPORT_BASE_URL}/reports/dashboard.html"
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*🎯 View Complete Security Dashboard*\nAccess detailed reports, screenshots, and analysis:"
        },
        "accessory": {
            "type": "button",
            "text": {
                "type": "plain_text",
                "text": "Open Dashboard",
                "emoji": True
            },
            "url": dashboard_url,
            "style": "primary"
        }
    })
    
    # Footer with scan metadata
    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": f"⏱️ _Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}_ | 🤖 _Powered by DirHunter AI_"
            }
        ]
    })
    
    # Prepare the payload
    payload = {
        "text": f"Security scan complete: {total_domains} domains, {total_findings} findings, {total_cves} CVEs",  # Fallback text
        "blocks": blocks[:50],  # Slack limit of 50 blocks
        "unfurl_links": False,
        "unfurl_media": False
    }

    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code != 200:
            print(f"[!] Slack alert failed: {response.text}")
        else:
            print(f"[+] Consolidated Slack alert sent successfully")
    except Exception as e:
        print(f"[!] Slack alert error: {e}")


def send_critical_alert(domain, critical_findings, webhook_url):
    """
    Send immediate alert for critical findings only
    """
    if not critical_findings or not webhook_url:
        return
    
    # Build critical alert message
    blocks = []
    
    # Header with urgency indicator
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"🚨 CRITICAL SECURITY FINDINGS - {domain}",
            "emoji": True
        }
    })
    
    # Alert context
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*Immediate attention required!*\n{len(critical_findings)} critical security findings detected on `{domain}`"
        }
    })
    
    # Divider
    blocks.append({"type": "divider"})
    
    # Critical findings details
    findings_text = "*Critical Findings:*\n\n"
    
    for finding in critical_findings[:10]:  # Limit to 10 to avoid message size limits
        status_icon = "🆕" if finding.get('finding_status') == 'new' else "🔄" if finding.get('finding_status') == 'changed' else "✅"
        findings_text += f"{status_icon} *[{finding.get('ai_tag', 'Unknown')}]*\n"
        findings_text += f"   └─ `{finding['url']}`\n"
        findings_text += f"   └─ Status: {finding.get('status', 'N/A')} | Length: {finding.get('length', 'N/A')} bytes\n\n"
    
    if len(critical_findings) > 10:
        findings_text += f"_...and {len(critical_findings) - 10} more critical findings_\n"
    
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": findings_text[:3000]  # Slack limit
        }
    })
    
    # Action buttons
    blocks.append({"type": "divider"})
    
    if REPORT_BASE_URL:
        dashboard_url = f"{REPORT_BASE_URL}/dashboard.html"
        domain_report_url = f"{REPORT_BASE_URL}/{domain}_tags.html"
        
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View Domain Report"
                    },
                    "url": domain_report_url,
                    "style": "danger"
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Open Dashboard"
                    },
                    "url": dashboard_url
                }
            ]
        })
    
    # Footer
    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": f"🚨 Critical Alert | {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Powered by DirHunter AI"
            }
        ]
    })
    
    # Send the alert
    payload = {
        "blocks": blocks,
        "text": f"🚨 CRITICAL: {len(critical_findings)} critical security findings on {domain}"
    }
    
    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
    except Exception as e:
        print(f"[!] Failed to send critical Slack alert: {e}")

def send_slack_alert(domain, findings, webhook_url):
    """
    Legacy function for single domain alerts - now calls consolidated version
    """
    send_consolidated_slack_alert({domain: findings}, webhook_url)


def send_rate_limit_alert(rate_limit_summary, webhook_url):
    """
    Send alert about rate limiting issues
    """
    if not rate_limit_summary:
        return
    
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "⚠️ Rate Limiting Detected",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Some domains returned 429 (Too Many Requests) errors during the scan.\n\n*🔄 Affected Domains:*"
            }
        }
    ]
    
    # Add domain details
    domain_text = ""
    for domain, count in rate_limit_summary.items():
        domain_text += f"• `{domain}`: {count} paths rate limited\n"
    
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": domain_text
        }
    })
    
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "*💡 Next Steps:*\n• These paths have been saved for retry\n• Run with `--retry-rate-limits` flag to scan them\n• The retry will use reduced rate limits"
        }
    })
    
    payload = {
        "text": "Rate limiting detected during scan",
        "blocks": blocks
    }
    
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 200:
            print(f"[+] Rate limit alert sent")
    except Exception as e:
        print(f"[!] Failed to send rate limit alert: {e}")

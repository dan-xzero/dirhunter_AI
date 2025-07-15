# File: dirhunter_ai/utils/reporter.py

import os
from datetime import datetime
from collections import defaultdict
import json
import requests
from functools import lru_cache
from utils.tech_helpers import extract_tech_and_cves, aggregate_cves, severity_from_count

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

def create_dashboard(all_domains_data):
    """
    Create a main dashboard that shows all domains and their findings
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
            secret_cnt = len(finding.get('download_meta', {}).get('th_secrets', [])) if finding.get('download_meta') else 0
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
    # Global CVE summary across all findings
    # ------------------------------------------------------------
    all_findings_list = [f for findings in all_domains_data.values() for f in findings if f]
    global_cve_total  = aggregate_cves(all_findings_list)["total"]
    
    # Build dashboard HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>DirHunter AI - Security Dashboard</title>
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
                transition: transform 0.2s, box-shadow 0.2s;
            }}
            .stat-card:hover {{
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0,0,0,0.12);
            }}
            .stat-card h3 {{
                margin: 0 0 0.5rem 0;
                color: #6b7280;
                font-size: 0.875rem;
                font-weight: 500;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            .stat-card .value {{
                font-size: 2.5rem;
                font-weight: 700;
                color: #1d1d1f;
                margin: 0;
            }}
            .stat-card.new {{ 
                border-left: 4px solid #10b981; 
                background: linear-gradient(to right, rgba(16, 185, 129, 0.05), white);
            }}
            .stat-card.changed {{ 
                border-left: 4px solid #f59e0b; 
                background: linear-gradient(to right, rgba(245, 158, 11, 0.05), white);
            }}
            .stat-card.total {{ 
                border-left: 4px solid #6366f1; 
                background: linear-gradient(to right, rgba(99, 102, 241, 0.05), white);
            }}
            .stat-card.existing {{
                border-left: 4px solid #6b7280;
                background: linear-gradient(to right, rgba(107, 114, 128, 0.05), white);
            }}
            .stat-card.secrets {{
                border-left: 4px solid #be123c;
                background: linear-gradient(to right, rgba(190, 18, 60, 0.05), white);
            }}
            .stat-card.cves {{
                border-left: 4px solid #b91c1c;
                background: linear-gradient(to right, rgba(185, 28, 28, 0.05), white);
            }}
            
            .section {{
                background: white;
                border-radius: 12px;
                padding: 2rem;
                margin-bottom: 2rem;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            }}
            .section h2 {{
                margin: 0 0 1.5rem 0;
                font-size: 1.5rem;
                font-weight: 600;
                color: #1d1d1f;
            }}
            
            .priority-grid {{
                display: grid;
                gap: 1rem;
            }}
            .priority-item {{
                background: #f9fafb;
                padding: 1rem;
                border-radius: 8px;
                border: 1px solid #e5e7eb;
                display: flex;
                align-items: center;
                gap: 1rem;
                transition: background 0.2s;
            }}
            .priority-item:hover {{
                background: #f3f4f6;
            }}
            .priority-item img {{
                width: 80px;
                height: 60px;
                object-fit: cover;
                border-radius: 4px;
                border: 1px solid #e5e7eb;
            }}
            .priority-item .details {{
                flex: 1;
            }}
            .priority-item .domain {{
                font-weight: 600;
                color: #6366f1;
                font-size: 0.875rem;
            }}
            .priority-item .url {{
                font-family: 'Courier New', monospace;
                font-size: 0.875rem;
                color: #4b5563;
                word-break: break-all;
                margin: 0.25rem 0;
            }}
            .priority-item .tags {{
                display: flex;
                gap: 0.5rem;
                flex-wrap: wrap;
            }}
            .tag {{
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 9999px;
                font-size: 0.75rem;
                font-weight: 500;
            }}
            .tag.critical {{ background: #fee2e2; color: #dc2626; }}
            .tag.high {{ background: #fef3c7; color: #d97706; }}
            .tag.medium {{ background: #dbeafe; color: #2563eb; }}
            .tag.new {{ background: #d1fae5; color: #059669; }}
            .tag.changed {{ background: #fed7aa; color: #ea580c; }}
            
            .domains-table {{
                width: 100%;
                border-collapse: collapse;
            }}
            .domains-table th {{
                text-align: left;
                padding: 0.75rem 1rem;
                border-bottom: 2px solid #e5e7eb;
                font-weight: 600;
                color: #6b7280;
                font-size: 0.875rem;
            }}
            .domains-table td {{
                padding: 1rem;
                border-bottom: 1px solid #f3f4f6;
            }}
            .domains-table tr:hover {{
                background: #f9fafb;
            }}
            .domains-table a {{
                color: #6366f1;
                text-decoration: none;
                font-weight: 500;
            }}
            .domains-table a:hover {{
                text-decoration: underline;
            }}
            
            .category-chart {{
                display: flex;
                gap: 1rem;
                align-items: center;
                margin-bottom: 1rem;
            }}
            .category-chart .bar {{
                flex: 1;
                background: #e5e7eb;
                height: 24px;
                border-radius: 4px;
                overflow: hidden;
                position: relative;
            }}
            .category-chart .fill {{
                height: 100%;
                background: #6366f1;
                transition: width 0.3s;
            }}
            .category-chart .label {{
                min-width: 150px;
                font-size: 0.875rem;
            }}
            .category-chart .count {{
                min-width: 50px;
                text-align: right;
                font-weight: 600;
            }}
            
            .timestamp {{
                text-align: center;
                color: #6b7280;
                font-size: 0.875rem;
                margin-top: 2rem;
            }}

            /* Filter controls */
            .filters {{
                display:flex;
                gap:0.75rem;
                flex-wrap:wrap;
                margin:1rem 0 1.5rem;
                align-items:center;
            }}
            .filters input {{
                flex:1 1 220px;
                padding:0.5rem 0.75rem;
                border:1px solid #d1d5db;
                border-radius:6px;
                font-size:0.9rem;
            }}
            .filter-btn {{
                padding:0.4rem 0.9rem;
                background:#e5e7eb;
                border:none;
                border-radius:6px;
                cursor:pointer;
                font-size:0.8rem;
            }}
            .filter-btn.active {{
                background:#6366f1;
                color:#fff;
            }}
            .hidden {{ display:none !important; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="container">
                <h1>🔍 DirHunter AI Security Dashboard</h1>
                <div class="subtitle">Comprehensive vulnerability discovery and analysis</div>
                {spark_svg}
            </div>
        </div>
        
        <div class="container">
            <!-- Statistics Cards -->
            <div class="stats-grid">
                <div class="stat-card total">
                    <h3>Total Domains</h3>
                    <p class="value">{total_domains}</p>
                </div>
                <div class="stat-card total">
                    <h3>Total Findings</h3>
                    <p class="value">{total_findings}</p>
                </div>
                <div class="stat-card new">
                    <h3>🆕 New Findings</h3>
                    <p class="value">{global_status_counts.get('new', 0)}</p>
                </div>
                <div class="stat-card changed">
                    <h3>🔄 Changed Findings</h3>
                    <p class="value">{global_status_counts.get('changed', 0)}</p>
                </div>
                <div class="stat-card existing">
                    <h3>✅ Existing Findings</h3>
                    <p class="value">{global_status_counts.get('existing', 0)}</p>
                </div>
                <div class="stat-card secrets">
                    <h3>🕵️ Secrets</h3>
                    <p class="value">{global_secret_count}</p>
                </div>
                <div class="stat-card cves">
                    <h3>⚠️ CVEs</h3>
                    <p class="value">{global_cve_total}</p>
                </div>
            </div>
            
            <!-- High Priority Findings -->
            <div class="section">
                <h2>🚨 High Priority Security Findings</h2>
                <div class="priority-grid">
    """
    
    # Add high priority findings
    for finding in high_priority_findings[:20]:  # Show top 20
        screenshot_html = ""
        if finding['screenshot'] and os.path.exists(finding['screenshot']):
            screenshot_rel = os.path.relpath(finding['screenshot'], HTML_REPORT_DIR)
            screenshot_html = f'<img src="{screenshot_rel}" alt="Screenshot">'
        
        status_tag = "new" if finding['status'] == 'new' else "changed" if finding['status'] == 'changed' else ""
        priority_tag = "critical" if finding['priority'] >= 9 else "high" if finding['priority'] >= 7 else "medium"
        
        html += f"""
                    <div class="priority-item">
                        {screenshot_html}
                        <div class="details">
                            <div class="domain">{finding['domain']}</div>
                            <div class="url">{finding['url']}</div>
                            <div class="tags">
                                <span class="tag {priority_tag}">{finding['category']}</span>
                                {f'<span class="tag {status_tag}">{finding["status"].upper()}</span>' if status_tag else ''}
                            </div>
                        </div>
                    </div>
        """
    
    html += """
                </div>
            </div>
            
            <!-- Category Distribution -->
            <div class="section">
                <h2>📊 Finding Categories</h2>
    """
    
    # Add category chart
    sorted_categories = sorted(global_category_counts.items(), key=lambda x: -x[1])
    max_count = max(global_category_counts.values()) if global_category_counts else 1
    
    for category, count in sorted_categories[:10]:  # Top 10 categories
        percentage = (count / max_count) * 100
        html += f"""
                <div class="category-chart">
                    <div class="label">{category}</div>
                    <div class="bar">
                        <div class="fill" style="width: {percentage}%"></div>
                    </div>
                    <div class="count">{count}</div>
                </div>
        """
    
    html += """
            </div>
            
            <!-- Domain Summary Table -->
            <div class="section">
                <h2>🌐 Domain Summary</h2>
                <div class="filters">
                    <input id="domainSearch" placeholder="🔍 Search domain..." />
                    <button class="filter-btn active" data-filter="all">All</button>
                    <button class="filter-btn" data-filter="new">New</button>
                    <button class="filter-btn" data-filter="changed">Changed</button>
                    <button class="filter-btn" data-filter="existing">Existing</button>
                    <button class="filter-btn" data-filter="secrets">Secrets</button>
                    <button class="filter-btn" data-filter="cves">CVEs</button>
                </div>
                <table class="domains-table">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Total</th>
                            <th>New</th>
                            <th>Changed</th>
                            <th>High Priority</th>
                            <th>Secrets</th>
                            <th>CVEs</th>
                            <th>Report</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    # Compliance-style reports removed – only technical reports remain
    # Add domain rows
    for domain in sorted(all_domains_data.keys()):
        findings = all_domains_data[domain]
        new_count = sum(1 for f in findings if f.get('finding_status') == 'new')
        changed_count = sum(1 for f in findings if f.get('finding_status') == 'changed')
        high_priority_count = sum(1 for f in findings if get_category_priority(f.get('ai_tag', 'Other')) >= 7)
        
        # Secrets count per domain
        secret_count = sum(len(f.get('download_meta', {}).get('th_secrets', [])) for f in findings if f and f.get('download_meta'))
        cve_count    = aggregate_cves(findings)["total"]
        existing_count = len(findings) - new_count - changed_count

        html += f"""
                        <tr data-domain="{domain}" data-new="{new_count}" data-changed="{changed_count}" data-existing="{existing_count}" data-secrets="{secret_count}" data-cves="{cve_count}">
                            <td><strong>{domain}</strong></td>
                            <td>{len(findings)}</td>
                            <td>{new_count}</td>
                            <td>{changed_count}</td>
                            <td>{high_priority_count}</td>
                            <td>{secret_count}</td>
                            <td>{cve_count}</td>
                            <td><a href="{domain}_tags.html">View</a></td>
                        </tr>
        """
    
    html += f"""
                    </tbody>
                </table>
            </div>
            
            <div class="timestamp">
                Generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S UTC')} – adaptive rate control active
            </div>
        </div>
        <script>
        (function() {{
            const searchInput = document.getElementById('domainSearch');
            const filterBtns  = document.querySelectorAll('.filter-btn');
            let currentFilter = 'all';

            function applyFilters() {{
                const q = (searchInput.value || '').toLowerCase();
                document.querySelectorAll('.domains-table tbody tr').forEach(row => {{
                    const domain    = row.dataset.domain.toLowerCase();
                    const newCnt    = parseInt(row.dataset.new);
                    const chgCnt    = parseInt(row.dataset.changed);
                    const existCnt  = parseInt(row.dataset.existing);
                    const secCnt    = parseInt(row.dataset.secrets);
                    const cvesCnt   = parseInt(row.dataset.cves);

                    let passesFilter = false;
                    switch(currentFilter) {{
                        case 'all':      passesFilter = true; break;
                        case 'new':      passesFilter = newCnt   > 0; break;
                        case 'changed':  passesFilter = chgCnt   > 0; break;
                        case 'existing': passesFilter = existCnt > 0; break;
                        case 'secrets':  passesFilter = secCnt   > 0; break;
                        case 'cves':     passesFilter = cvesCnt  > 0; break;
                    }}

                    const matchesSearch = q === '' || domain.includes(q);
                    if(passesFilter && matchesSearch) {{
                        row.classList.remove('hidden');
                    }} else {{
                        row.classList.add('hidden');
                    }}
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
    
    # Save dashboard
    with open(dashboard_file, "w", encoding="utf-8") as f:
        f.write(html)
    
    print(f"[+] Dashboard created: {dashboard_file}")
    return dashboard_file


def export_tag_based_reports(domain, findings, output_dir=HTML_REPORT_DIR):
    """
    Creates enhanced reports with better styling and finding status indicators
    """
    os.makedirs(output_dir, exist_ok=True)

    # Group results by AI tag
    grouped = defaultdict(list)
    for f in findings:
        if f is None:
            continue
        tag = f.get("ai_tag", "Other")
        grouped[tag].append(f)

    # Build domain tag index
    tag_index_file = os.path.join(output_dir, f"{domain}_tags.html")

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
                transition: transform 0.2s, box-shadow 0.2s;
                cursor: pointer;
            }}
            .tag-card:hover {{
                transform: translateY(-4px);
                box-shadow: 0 8px 16px rgba(0,0,0,0.12);
            }}
            .tag-card .thumbnail {{
                width: 100%;
                height: 180px;
                object-fit: cover;
                background: #f3f4f6;
            }}
            .tag-card .content {{
                padding: 1.5rem;
            }}
            .tag-card h3 {{
                margin: 0 0 0.5rem 0;
                font-size: 1.25rem;
                font-weight: 600;
            }}
            .tag-card .count {{
                color: #6b7280;
                font-size: 0.875rem;
            }}
            .tag-card .status-badges {{
                margin-top: 0.5rem;
                display: flex;
                gap: 0.5rem;
            }}
            .badge {{
                display: inline-block;
                padding: 0.25rem 0.75rem;
                border-radius: 9999px;
                font-size: 0.75rem;
                font-weight: 500;
            }}
            .badge.new {{ background: #d1fae5; color: #059669; }}
            .badge.changed {{ background: #fed7aa; color: #ea580c; }}
            .badge.existing {{ background: #e0e7ff; color: #4338ca; }}
            a {{ text-decoration: none; color: inherit; }}
        </style>
    </head>
    <body>
        <input id="searchBox" placeholder="🔍 Search findings... (supports URL & tag)" />
        <div class="header">
            <div class="container">
                <h1>{domain}</h1>
                <div class="breadcrumb">
                    <a href="dashboard.html">← Back to Dashboard</a> / Security Findings by Category
                </div>
            </div>
        </div>
        
        <div class="container">
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
        subpage_name = f"{domain}_tag_{tag_slug}.html"

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
        make_enhanced_subpage_for_tag(domain, tag, items, subpage_name, output_dir)

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


def make_enhanced_subpage_for_tag(domain, tag, items, subpage_name, output_dir):
    """
    Creates an enhanced subpage with better styling and status indicators
    """
    # Remove any None placeholders
    items = [itm for itm in items if itm is not None]
    if not items:
        return  # nothing to render

    subpage_path = os.path.join(output_dir, subpage_name)

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
                    <a href="{domain}_tags.html">{domain}</a> / 
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
                                <strong>VirusTotal:</strong> {f.get('vt_status', 'N/A')}
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
        vt = f.get('vt') or {}
        vt_badge = ""
        if vt:
            pos = vt.get('positives', 0)
            total = vt.get('total', 0)
            color = '#dc2626' if pos else '#059669'
            vt_badge = f"<span style='background:{color};color:#fff;padding:2px 6px;border-radius:4px;font-size:0.75rem' title='VirusTotal positives/total'>VT {pos}/{total}</span>"

        # Download meta for secrets
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
        secret_cnt = len(download_meta.get('th_secrets', []))
        secret_badge = ""
        if secret_cnt:
            secret_badge = f"<span style='background:#be123c;color:#fff;padding:2px 6px;border-radius:4px;font-size:0.75rem' title='Secrets detected by TruffleHog'>SECRETS {secret_cnt}</span>"

        if vt_badge or cve_badge or secret_badge or tech_badge_html:
            html += f"""
                            <div class="metadata-item">{vt_badge} {cve_badge} {secret_badge} {tech_badge_html}</div>
            """

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
                <a href="{domain}_tags.html" style="color: #6366f1;">← Back to {domain} overview</a>
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

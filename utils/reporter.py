# File: dirhunter_ai/utils/reporter.py

import os
from datetime import datetime
from collections import defaultdict

HTML_REPORT_DIR = "results/html"

def export_tag_based_reports(domain, findings, output_dir=HTML_REPORT_DIR):
    """
    Creates:
    1) A top-level 'tag index' for the domain with one representative screenshot per AI tag.
    2) For each AI tag, a sub-page listing all URLs with that tag, including screenshots.

    Example:
        domain_tags.html        # The top-level index of tags for this domain
        domain_tag_<tag>.html   # One page per tag with all matched items
    """
    os.makedirs(output_dir, exist_ok=True)

    # Group results by AI tag
    grouped = defaultdict(list)
    for f in findings:
        tag = f.get("ai_tag", "Other")
        grouped[tag].append(f)

    # Build domain tag index
    tag_index_file = os.path.join(output_dir, f"{domain}_tags.html")

    # We'll store <li> items here
    li_items = []

    for tag, items in grouped.items():
        # Sort or pick the first item as representative
        rep_item = items[0]

        # We'll show a small thumbnail or 'N/A'
        if rep_item.get("screenshot"):
            screenshot_rel = os.path.relpath(rep_item["screenshot"], output_dir)
            rep_img_html = f"<img src='../results/{screenshot_rel}' width='200' style='border:1px solid #ccc;'/>"
        else:
            rep_img_html = "N/A"

        # Slugify tag for link usage
        tag_slug = slugify_tag(tag)

        # The sub-page is domain + tag slug
        subpage_name = f"{domain}_tag_{tag_slug}.html"

        # Each <li> is: [thumbnail] + link to subpage
        li_items.append(f"""
            <li style="margin-bottom:15px;">
                <a href="{subpage_name}">
                    <h3>{tag} ({len(items)})</h3>
                    {rep_img_html}
                </a>
            </li>
        """)

        # Now generate the sub-page
        make_subpage_for_tag(domain, tag, items, subpage_name, output_dir)

    # Build final index HTML
    index_html = f"""
    <html>
    <head>
        <title>{domain} - Tag Index</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            ul {{ list-style-type: none; padding: 0; }}
            li {{ margin: 10px 0; }}
            img {{ border-radius: 4px; }}
        </style>
    </head>
    <body>
        <h1>{domain} - Tag Index</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <ul>
        {''.join(li_items)}
        </ul>
    </body>
    </html>
    """

    # Save domain tag index
    with open(tag_index_file, "w", encoding="utf-8") as f:
        f.write(index_html)

    print(f"[+] Tag index for '{domain}' saved to: {tag_index_file}")


def make_subpage_for_tag(domain, tag, items, subpage_name, output_dir):
    """
    Creates a separate HTML page listing all items for a given tag.
    """
    rows = []
    for f in items:
        screenshot_html = "N/A"
        if f.get("screenshot"):
            screenshot_rel = os.path.relpath(f["screenshot"], output_dir)
            screenshot_html = f"<img src='../results/{screenshot_rel}' width='300'>"

        row = f"""
        <tr>
            <td><a href="{f['url']}" target="_blank">{f['url']}</a></td>
            <td>{f.get('status','')}</td>
            <td>{f.get('length','')}</td>
            <td>{screenshot_html}</td>
        </tr>
        """
        rows.append(row)

    subpage_path = os.path.join(output_dir, subpage_name)

    html = f"""
    <html>
    <head>
        <title>{domain} - {tag}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ padding: 8px 12px; border: 1px solid #ccc; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            img {{ border: 1px solid #ddd; border-radius: 4px; }}
        </style>
    </head>
    <body>
        <h1>{tag} for <code>{domain}</code></h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Length</th>
                    <th>Screenshot</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
        <p><a href="{domain}_tags.html">Back to Tag Index</a></p>
    </body>
    </html>
    """

    with open(subpage_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Created subpage: {subpage_path} for tag={tag}")


def slugify_tag(tag):
    """
    Converts a tag string into a filesystem-safe slug, e.g.:
    'Admin Panel' -> 'admin_panel'
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

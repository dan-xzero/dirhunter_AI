import json, threading
from datetime import datetime
from pathlib import Path

HIST_FILE = Path("db/run_history.json")
HIST_FILE.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()
MAX_ENTRIES = 50

def _load():
    if HIST_FILE.exists():
        try:
            return json.loads(HIST_FILE.read_text())
        except Exception:
            pass
    return []

def _save(data):
    HIST_FILE.write_text(json.dumps(data, indent=2))

def record_run(total_domains:int, new_findings:int, changed_findings:int):
    entry = {
        "ts": datetime.utcnow().isoformat(timespec="seconds"),
        "domains": total_domains,
        "new": new_findings,
        "changed": changed_findings
    }
    with _lock:
        data = _load()
        data.append(entry)
        if len(data) > MAX_ENTRIES:
            data = data[-MAX_ENTRIES:]
        _save(data)

def get_history(limit:int=20):
    data = _load()
    return data[-limit:] 

def update_run_history(results, domains_with_wordlists):
    """Update run history with results from the current scan
    
    Args:
        results: Dictionary mapping domains to their findings
        domains_with_wordlists: List of (domain, wordlist) tuples that were scanned
    """
    # Calculate key statistics
    total_domains = len(domains_with_wordlists)
    
    # Count findings by status
    if results:
        total_findings = sum(len(findings) for findings in results.values())
        new_findings = sum(sum(1 for f in fs if f.get('finding_status') == 'new') for fs in results.values())
        changed_findings = sum(sum(1 for f in fs if f.get('finding_status') == 'changed') for fs in results.values())
    else:
        total_findings = 0
        new_findings = 0
        changed_findings = 0
    
    # Record the run
    record_run(total_domains, new_findings, changed_findings) 
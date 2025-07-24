# File: dirhunter_ai/utils/scanner.py
import subprocess, json, tempfile, os, shlex, requests
from pathlib import Path
from utils.db_handler import track_rate_limit, get_pending_rate_limits, mark_rate_limit_completed
from utils.rate_control import get_rate, update_stats
from utils.ffuf_progress import get_last_position, update_position

# Cache ffuf capability detection
_FFUF_SUPPORTS_RESUME = None


def _ffuf_supports_resume():
    """Return True if installed ffuf binary supports --resume-from flag."""
    global _FFUF_SUPPORTS_RESUME  # pylint: disable=global-statement
    if _FFUF_SUPPORTS_RESUME is not None:
        return _FFUF_SUPPORTS_RESUME

    try:
        out = subprocess.run(["ffuf", "-h"], capture_output=True, text=True, timeout=5)
        _FFUF_SUPPORTS_RESUME = "-resume-from" in out.stdout
    except Exception:
        _FFUF_SUPPORTS_RESUME = False
    return _FFUF_SUPPORTS_RESUME


def smart_resolve_scheme(domain: str) -> str:
    """Return a fully-qualified base URL (no trailing slash) for the given domain.

    1. Accepts inputs with or without scheme.
    2. Removes any *trailing* slashes to avoid the dreaded ``//`` duplication when
       we later append paths (e.g. ``https://example.com`` instead of
       ``https://example.com/``).
    3. Prefers HTTPS but gracefully falls back to HTTP when the HEAD request
       fails.
    """

    # 1️⃣  Normalise – strip *all* trailing slashes first so we never propagate them
    domain = domain.rstrip("/")

    # 2️⃣  If the caller already provided a scheme, we are done after normalising.
    if domain.startswith("http://") or domain.startswith("https://"):
        return domain  # already sans trailing slash

    # 3️⃣  Otherwise, try HTTPS then HTTP
    https_url = f"https://{domain}"
    try:
        resp = requests.head(https_url, timeout=5, allow_redirects=True)
        if resp.status_code < 500:
            print(f"[+] Using HTTPS → {https_url}")
            return https_url  # Already has no trailing slash
    except Exception:
        print(f"[!] HTTPS failed, falling back to HTTP")

    http_url = f"http://{domain}"
    print(f"[+] Using HTTP → {http_url}")
    return http_url  # No trailing slash


def run_ffuf(domain,
             wordlist,
             extensions,
             threads,
             rate      = 50,
             delay     = None,
             resume_from = None
             ):

    # ------------------------------------------------------------
    # Sanitize wordlist – remove a single leading '/' if present
    # ------------------------------------------------------------
    sanitized_wordlist = wordlist
    try:
        # Only create a sanitized copy once per original wordlist path
        # Cache file alongside original with .noslash suffix
        p = Path(wordlist)
        if p.exists():
            sanitized = p.with_suffix(p.suffix + ".noslash")
            # Always regenerate to pick up any sanitation rule changes
            with p.open("r", encoding="utf-8", errors="ignore") as src, sanitized.open("w", encoding="utf-8") as dst:
                for line in src:
                    ln = line.rstrip("\n\r")
                    import re as _re  # local import to avoid top-level dependency
                    if ln.startswith('/') and not ln.startswith('//'):
                        ln = ln[1:]
                    # Collapse repeated slashes anywhere else in the path (e.g., "admin//upload")
                    ln = _re.sub(r'/+', '/', ln)
                    dst.write(ln + "\n")
            sanitized_wordlist = str(sanitized)
    except Exception:
        # Fallback to original list on any error
        sanitized_wordlist = wordlist

    domain = smart_resolve_scheme(domain)

    # Determine adaptive rate
    adaptive_rate = get_rate(domain.replace("http://", "").replace("https://", ""), rate)

    url           = f"{domain}/FUZZ"
    output_file   = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name
    extension_arg = ",".join(extensions)

    cmd = [
        "ffuf",
        "-u",  url,
        "-w",  sanitized_wordlist,
        # "-e",  extension_arg,
        "-t",  str(threads),
        "-o",  output_file,
        "-of", "json",
        "-fc", "404","403",  # Removed 429 from filter to track rate limits
        "-v",
        # "-x", "http://127.0.0.1:8080",
        "-H", "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36-FUZZ"
    ]

    if adaptive_rate and int(adaptive_rate) > 0:
        cmd += ["-rate", str(adaptive_rate)]
    if delay:
        cmd += ["-p", str(delay)]
    
    # Allow manual override but otherwise use stored progress
    if resume_from is None and _ffuf_supports_resume():
        resume_from = get_last_position(domain.replace("http://", "").replace("https://", ""), wordlist)

    if resume_from and _ffuf_supports_resume():
        cmd += ["-resume-from", str(resume_from)]

    # --- run -----------------------------------------------------------
    print(f"[~] FFUF command:\n    {shlex.join(cmd)}")
    save_ffuf_command(domain, cmd)
    subprocess.run(cmd)

    # --- parse ---------------------------------------------------------
    results = []
    rate_limited_paths = []
    
    try:
        with open(output_file, encoding="utf-8") as f:
            data = json.load(f)
            
            # Track wordlist for rate limit recovery
            wordlist_used = data.get("config", {}).get("wordlist", wordlist)
            
            result_items = data.get("results", [])
            total_requests = len(result_items)

            max_pos = resume_from or 0
            for idx, item in enumerate(result_items):
                result = {
                    "url":    item["url"],
                    "status": item["status"],
                    "length": item["length"],
                    "words":  item["words"],
                    "lines":  item["lines"],
                    "path":   item["input"].get("FUZZ", ""),
                    "position": idx  # Track position in wordlist
                }
                
                # Track rate limited paths
                if item["status"] == 429:
                    rate_limited_paths.append({
                        "path": result["path"],
                        "position": idx
                    })
                    # Track in database
                    track_rate_limit(domain.replace("http://", "").replace("https://", ""), 
                                   result["path"], idx)
                else:
                    results.append(result)

                if idx > max_pos:
                    max_pos = idx
                    
    except Exception as e:
        print(f"[!] JSON parse error: {e}")
    
    # Report rate limits if found
    if rate_limited_paths:
        print(f"[!] Found {len(rate_limited_paths)} rate-limited (429) responses")
        print(f"[!] These paths will be retried later with reduced rate")
    
    # Update adaptive rate stats
    try:
        update_stats(domain.replace("http://", "").replace("https://", ""),
                     total_requests=len(results) + len(rate_limited_paths),
                     num_429=len(rate_limited_paths))
    except Exception:
        pass

    # Persist new progress index
    try:
        update_position(domain.replace("http://", "").replace("https://", ""), wordlist_used, max_pos)
    except Exception:
        pass

    return results, rate_limited_paths


def retry_rate_limited_paths(domain, wordlist, extensions, threads=10):
    """Retry paths that were rate limited in previous runs"""
    domain_clean = domain.replace("http://", "").replace("https://", "")
    pending = get_pending_rate_limits(domain_clean)
    
    if not pending:
        print(f"[+] No rate-limited paths to retry for {domain}")
        return []
    
    print(f"[~] Retrying {len(pending)} rate-limited paths for {domain}")
    
    # Create temporary wordlist with only the rate limited paths
    temp_wordlist = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
    for _, path, _, _ in pending:
        temp_wordlist.write(path + "\n")
    temp_wordlist.close()
    
    # Run with much lower rate
    results, still_limited = run_ffuf(
        domain=domain,
        wordlist=temp_wordlist.name,
        extensions=extensions,
        threads=5,  # Lower threads
        rate=10,    # Much lower rate
        delay="1.0-3.0"  # Higher delay
    )
    
    # Mark successful paths as completed
    for result in results:
        mark_rate_limit_completed(domain_clean, result["path"])
    
    # Cleanup temp file
    os.unlink(temp_wordlist.name)
    
    return results


def save_ffuf_command(domain, cmd):
    safe = domain.replace("http://", "").replace("https://", "").replace("/", "_")
    os.makedirs(f"results/raw/{safe}", exist_ok=True)
    script = f"results/raw/{safe}/command.sh"
    with open(script, "w") as f:
        f.write("#!/bin/bash\n" + " ".join(cmd) + "\n")
    os.chmod(script, 0o755)
    print(f"[~] FFUF command saved → {script}")

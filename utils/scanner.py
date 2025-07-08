# File: dirhunter_ai/utils/scanner.py
import subprocess, json, tempfile, os, shlex, requests
from utils.db_handler import track_rate_limit, get_pending_rate_limits, mark_rate_limit_completed

def smart_resolve_scheme(domain):
    if domain.startswith("http://") or domain.startswith("https://"):
        return domain.rstrip("/")

    https_url = f"https://{domain}"
    try:
        resp = requests.head(https_url, timeout=5, allow_redirects=True)
        if resp.status_code < 500:
            print(f"[+] Using HTTPS → {https_url}")
            return https_url
    except Exception:
        print(f"[!] HTTPS failed, falling back to HTTP")

    http_url = f"http://{domain}"
    print(f"[+] Using HTTP → {http_url}")
    return http_url.rstrip("/")


def run_ffuf(domain,
             wordlist,
             extensions,
             threads,
             rate      = 50,
             delay     = None,
             resume_from = None
             ):
    domain = smart_resolve_scheme(domain)

    url           = f"{domain}/FUZZ"
    output_file   = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name
    extension_arg = ",".join(extensions)

    cmd = [
        "ffuf",
        "-u",  url,
        "-w",  wordlist,
        # "-e",  extension_arg,
        "-t",  str(threads),
        "-o",  output_file,
        "-of", "json",
        "-fc", "404",  # Removed 429 from filter to track rate limits
        "-v",
        # "-x", "http://127.0.0.1:8080",
        "-H", "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36-FUZZ"
    ]

    if rate and int(rate) > 0:
        cmd += ["-rate", str(rate)]
    if delay:
        cmd += ["-p", str(delay)]
    
    # Resume from specific position if retrying rate limited paths
    if resume_from:
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
            
            for idx, item in enumerate(data.get("results", [])):
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
                    
    except Exception as e:
        print(f"[!] JSON parse error: {e}")
    
    # Report rate limits if found
    if rate_limited_paths:
        print(f"[!] Found {len(rate_limited_paths)} rate-limited (429) responses")
        print(f"[!] These paths will be retried later with reduced rate")
    
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

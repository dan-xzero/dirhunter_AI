# File: dirhunter_ai/utils/scanner.py
import subprocess, json, tempfile, os, shlex, requests

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
             delay     = None
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
        "-fc", "404,429",
        "-v",
        # "-x", "http://127.0.0.1:8080",
        "-H", "User-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36-FUZZ"
    ]

    if rate and int(rate) > 0:
        cmd += ["-rate", str(rate)]
    if delay:
        cmd += ["-p", str(delay)]

    # --- run -----------------------------------------------------------
    print(f"[~] FFUF command:\n    {shlex.join(cmd)}")
    save_ffuf_command(domain, cmd)
    subprocess.run(cmd)

    # --- parse ---------------------------------------------------------
    results = []
    try:
        with open(output_file, encoding="utf-8") as f:
            for item in json.load(f).get("results", []):
                results.append({
                    "url":    item["url"],
                    "status": item["status"],
                    "length": item["length"],
                    "words":  item["words"],
                    "lines":  item["lines"],
                    "path":   item["input"].get("FUZZ", "")
                })
    except Exception as e:
        print(f"[!] JSON parse error: {e}")
    return results


def save_ffuf_command(domain, cmd):
    safe = domain.replace("http://", "").replace("https://", "").replace("/", "_")
    os.makedirs(f"results/raw/{safe}", exist_ok=True)
    script = f"results/raw/{safe}/command.sh"
    with open(script, "w") as f:
        f.write("#!/bin/bash\n" + " ".join(cmd) + "\n")
    os.chmod(script, 0o755)
    print(f"[~] FFUF command saved → {script}")

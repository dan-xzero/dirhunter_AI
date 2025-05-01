# File: dirhunter_ai/utils/scanner.py
import subprocess, json, tempfile, os, shlex

def run_ffuf(domain,
             wordlist,
             extensions,
             threads,
             rate      = 50,   # max requests‑per‑second   (None → no limit)
             delay     = None  # e.g. "0.1"  or  "0.2‑1.0"  (string accepted by ‑p)
             ):
    """
    :param rate:  int | None   –  FFUF ‑rate  (reqs/sec).  0 or None disables.
    :param delay: str | None   –  FFUF ‑p     fixed or random delay between requests
                                   Examples:  "0.1"   or  "0.2-1.0"
    """

    domain = domain.strip().rstrip("/")
    if not domain.startswith(("http://", "https://")):
        domain = f"http://{domain}"

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

        # "-r",                 # follow redirects
        # "-ac",                # auto‑calibration
        "-fc", "404,429",     # filter noise
        "-v",
        # "-x", "http://127.0.0.1:8080",
        "-H", "User-agent:  Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36-FUZZ"
    ]

    # apply rate limit / delay if given
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

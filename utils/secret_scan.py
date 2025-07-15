import json, subprocess, tempfile, os, shutil, logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

TRUFFLE_CMD = shutil.which("trufflehog")


def scan_secrets_bytes(data: bytes, max_findings: int = 20) -> List[Dict[str, Any]]:
    """Run trufflehog (verified) against given bytes. Returns list of findings."""
    if TRUFFLE_CMD is None:
        logger.debug("trufflehog not found in PATH – skipping secret scan")
        return []

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    findings = []
    try:
        # Run trufflehog filesystem scan (no git parsing) in JSON output
        # Use --no-update to disable DB update, --only-verified to reduce false positives
        cmd = [TRUFFLE_CMD, "filesystem", "--no-git", "--json", tmp_path, "--only-verified"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = proc.stdout.splitlines()
        for line in output:
            try:
                obj = json.loads(line)
                findings.append({
                    "redacted": obj.get("Redacted") or obj.get("redacted"),
                    "reason": obj.get("Reason") or obj.get("reason"),
                })
                if len(findings) >= max_findings:
                    break
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"trufflehog scan failed: {e}")
    finally:
        os.unlink(tmp_path)

    return findings 
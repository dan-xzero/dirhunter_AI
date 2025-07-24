import json, subprocess, tempfile, os, shutil, logging
from typing import List, Dict, Any
import sys

logger = logging.getLogger(__name__)

# Try direct binary first; fallback to module execution
_cmd = shutil.which("trufflehog")
if not _cmd:
    # Use the python module if installed (pip install trufflehog)
    _cmd = f"{sys.executable} -m trufflehog"  # type: ignore
TRUFFLE_CMD = _cmd if _cmd else None


def scan_secrets_bytes(data: bytes, max_findings: int = 20) -> List[Dict[str, Any]]:
    """Run trufflehog (verified) against given bytes. Returns list of findings."""
    if TRUFFLE_CMD is None:
        logger.debug("trufflehog not found in PATH – skipping secret scan")
        return []

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    findings = []
    logger.info("[trufflehog] Scanning temporary file (%d bytes) for secrets", os.path.getsize(tmp_path))
    try:
        # Run trufflehog filesystem scan (no git parsing) in JSON output
        # Use --no-update to disable DB update, --only-verified to reduce false positives
        import shlex
        cmd_parts = shlex.split(TRUFFLE_CMD)
        cmd = cmd_parts + ["filesystem", "--json", "--results=verified", tmp_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout.splitlines()
        for line in output:
            try:
                obj = json.loads(line)
                findings.append({
                    "raw": obj.get("Raw") or obj.get("raw") or obj.get("RawV2"),
                    "redacted": obj.get("Redacted") or obj.get("redacted"),
                    "reason": obj.get("Reason") or obj.get("reason") or obj.get("DetectorName"),
                })
                if len(findings) >= max_findings:
                    break
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"trufflehog scan failed: {e}")
    finally:
        os.unlink(tmp_path)

    logger.info("[trufflehog] Scan complete – %d findings", len(findings))

    return findings 
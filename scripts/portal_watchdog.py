#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = REPO_ROOT / "frontend"

SERVICES = (
    "postgresql",
    "redis-server",
    "dirhunter-api",
    "dirhunter-worker",
    "dirhunter-ui",
)
TIMERS = ("dirhunter-portal-watchdog.timer",)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Auto-heal the DirHunter portal service stack.")
    parser.add_argument("--once", action="store_true", help="Run one health check and exit.")
    parser.add_argument("--interval", type=int, default=int(os.getenv("PORTAL_WATCHDOG_INTERVAL", "120")))
    parser.add_argument("--timeout", type=int, default=int(os.getenv("PORTAL_WATCHDOG_TIMEOUT", "20")))
    parser.add_argument("--no-repair", action="store_true", help="Only report failures; do not restart/rebuild.")
    return parser.parse_args()


def log(message: str) -> None:
    print(f"[portal-watchdog] {message}", flush=True)


def run(command: list[str], *, timeout: int = 60, cwd: Path | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    log("run " + " ".join(command))
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=check,
    )


def systemctl(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return run(["systemctl", *args], timeout=timeout)


def is_active(unit: str) -> bool:
    result = systemctl("is-active", "--quiet", unit, timeout=15)
    return result.returncode == 0


def heal_unit(unit: str, *, no_repair: bool) -> bool:
    if is_active(unit):
        return False
    log(f"{unit} is not active")
    if no_repair:
        return True
    systemctl("reset-failed", unit, timeout=30)
    systemctl("restart", unit, timeout=90)
    if not is_active(unit):
        raise RuntimeError(f"{unit} is still not active after restart")
    log(f"{unit} restarted")
    return True


def heal_timer(timer: str, *, no_repair: bool) -> bool:
    if is_active(timer):
        return False
    log(f"{timer} is not active")
    if no_repair:
        return True
    systemctl("enable", "--now", timer, timeout=60)
    if not is_active(timer):
        raise RuntimeError(f"{timer} is still not active after enable --now")
    log(f"{timer} enabled and started")
    return True


def fetch(url: str, *, timeout: int) -> tuple[int, str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "DirHunterPortalWatchdog/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(512_000).decode("utf-8", errors="replace")
        return response.status, response.headers.get("content-type", ""), body


def http_ok(url: str, *, timeout: int) -> bool:
    try:
        status, _, _ = fetch(url, timeout=timeout)
        return 200 <= status < 400
    except Exception as exc:
        log(f"http check failed url={url} error={type(exc).__name__}: {exc}")
        return False


def wait_http_ok(url: str, *, timeout: int, attempts: int = 5, delay: float = 2.0) -> bool:
    for attempt in range(1, attempts + 1):
        if http_ok(url, timeout=timeout):
            return True
        if attempt < attempts:
            time.sleep(delay)
    return False


def ensure_api(*, timeout: int, no_repair: bool) -> bool:
    if wait_http_ok("http://127.0.0.1:8000/healthz", timeout=timeout, attempts=3, delay=1.0):
        return False
    log("api health endpoint is down")
    if no_repair:
        return True
    heal_unit("dirhunter-api", no_repair=False)
    if not wait_http_ok("http://127.0.0.1:8000/healthz", timeout=timeout, attempts=8, delay=2.0):
        raise RuntimeError("api health endpoint is still down after restart")
    return True


def asset_paths(html: str) -> list[str]:
    return sorted(set(re.findall(r'(?:href|src)="([^"]*_next/static/[^"]+)"', html)))


def standalone_assets_present() -> bool:
    return (FRONTEND_DIR / ".next/standalone/.next/static").is_dir() and (FRONTEND_DIR / ".next/standalone/public").is_dir()


def ensure_ui_assets(*, timeout: int, no_repair: bool) -> bool:
    if not standalone_assets_present():
        log("standalone static/public directories are missing")
        if no_repair:
            return True
        rebuild_ui(timeout=max(180, timeout * 6))
        systemctl("restart", "dirhunter-ui", timeout=90)
        return True

    try:
        _, _, html = fetch("http://127.0.0.1:8080/", timeout=timeout)
        paths = asset_paths(html)
        if not paths:
            raise RuntimeError("home page did not include _next/static assets")
        for path in paths[:8]:
            fetch("http://127.0.0.1:8080" + path, timeout=timeout)
        return False
    except (urllib.error.HTTPError, urllib.error.URLError, RuntimeError, TimeoutError) as exc:
        log(f"ui asset check failed error={type(exc).__name__}: {exc}")
        if no_repair:
            return True
        rebuild_ui(timeout=max(240, timeout * 8))
        systemctl("restart", "dirhunter-ui", timeout=90)
        return True


def rebuild_ui(*, timeout: int) -> None:
    log("rebuilding frontend standalone bundle")
    if not (FRONTEND_DIR / "node_modules/.package-lock.json").exists():
        run(["npm", "ci"], cwd=FRONTEND_DIR, timeout=timeout, check=True)
    run(["npm", "run", "build"], cwd=FRONTEND_DIR, timeout=timeout, check=True)
    if not standalone_assets_present():
        raise RuntimeError("frontend build completed but standalone assets are still missing")


def ensure_nginx(*, timeout: int, no_repair: bool) -> bool:
    if wait_http_ok("http://127.0.0.1:8080/", timeout=timeout, attempts=3, delay=1.0):
        return False
    log("nginx portal endpoint is down")
    if no_repair:
        return True
    test = run(["nginx", "-t"], timeout=30)
    if test.returncode == 0:
        systemctl("reload", "nginx", timeout=30)
    else:
        log(test.stdout.strip())
    systemctl("restart", "nginx", timeout=60)
    if not wait_http_ok("http://127.0.0.1:8080/", timeout=timeout, attempts=10, delay=2.0):
        raise RuntimeError("nginx portal endpoint is still down after restart")
    return True


def check_once(args: argparse.Namespace) -> int:
    changes = 0
    for service in SERVICES:
        changes += int(heal_unit(service, no_repair=args.no_repair))
    for timer in TIMERS:
        changes += int(heal_timer(timer, no_repair=args.no_repair))
    changes += int(ensure_api(timeout=args.timeout, no_repair=args.no_repair))
    changes += int(ensure_nginx(timeout=args.timeout, no_repair=args.no_repair))
    changes += int(ensure_ui_assets(timeout=args.timeout, no_repair=args.no_repair))
    log(f"health check complete changes={changes}")
    return changes


def main() -> int:
    args = parse_args()
    while True:
        try:
            check_once(args)
        except Exception as exc:
            log(f"health check failed: {type(exc).__name__}: {exc}")
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_ROOT="${DIRHUNTER_INSTALL_ROOT:-/opt/dirhunter_AI}"
ENV_DIR="/etc/dirhunter"

mkdir -p "$ENV_DIR"

if [[ ! -e "$INSTALL_ROOT" ]]; then
  ln -s "$REPO_ROOT" "$INSTALL_ROOT"
fi

if [[ ! -f "$ENV_DIR/dirhunter.env" ]]; then
  install -m 0600 "$REPO_ROOT/deploy/dirhunter.env.example" "$ENV_DIR/dirhunter.env"
fi

install -m 0644 "$REPO_ROOT/deploy/dirhunter-api.service" /etc/systemd/system/dirhunter-api.service
install -m 0644 "$REPO_ROOT/deploy/dirhunter-worker.service" /etc/systemd/system/dirhunter-worker.service
install -m 0644 "$REPO_ROOT/deploy/dirhunter-slack.service" /etc/systemd/system/dirhunter-slack.service
install -m 0644 "$REPO_ROOT/deploy/dirhunter-ui.service" /etc/systemd/system/dirhunter-ui.service
install -m 0644 "$REPO_ROOT/deploy/dirhunter-scan-watchdog.service" /etc/systemd/system/dirhunter-scan-watchdog.service
install -m 0644 "$REPO_ROOT/deploy/dirhunter-scan-watchdog.timer" /etc/systemd/system/dirhunter-scan-watchdog.timer
install -m 0644 "$REPO_ROOT/deploy/dirhunter-portal-watchdog.service" /etc/systemd/system/dirhunter-portal-watchdog.service
install -m 0644 "$REPO_ROOT/deploy/dirhunter-portal-watchdog.timer" /etc/systemd/system/dirhunter-portal-watchdog.timer
install -m 0644 "$REPO_ROOT/deploy/logrotate/dirhunter" /etc/logrotate.d/dirhunter

systemctl daemon-reload
systemctl enable dirhunter-api dirhunter-worker dirhunter-slack dirhunter-ui dirhunter-portal-watchdog.timer

echo "Installed DirHunter services. Edit $ENV_DIR/dirhunter.env before starting them."

#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="${DIRHUNTER_REPO_ROOT:-/opt/dirhunter_AI}"
ENV_FILE="${DIRHUNTER_ENV_FILE:-/etc/dirhunter/dirhunter.env}"
BACKUP_DIR="${DIRHUNTER_BACKUP_DIR:-/var/backups/dirhunter}"

set_kv() {
  local key="$1"
  local value="$2"
  mkdir -p "$(dirname "$ENV_FILE")"
  touch "$ENV_FILE"
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s#^${key}=.*#${key}=${value}#" "$ENV_FILE"
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
}

set_kv USE_PG 1
set_kv USE_LEGACY_HTML 0
set_kv USE_NEW_SLACK 1

install -m 0644 "$PROJECT_DIR/deploy/logrotate/dirhunter" /etc/logrotate.d/dirhunter

: > "$PROJECT_DIR/cron.log"

if [[ -d "$PROJECT_DIR/results/html" ]]; then
  find "$PROJECT_DIR/results/html" -maxdepth 1 \( -name "*.html" -o -name "*_tag_*" \) -exec rm -rf {} +
fi

mkdir -p "$BACKUP_DIR"
cd "$PROJECT_DIR"
PGHOST="${PGHOST:-127.0.0.1}" PGPASSWORD="${PGPASSWORD:-dirhunter}" DIRHUNTER_BACKUP_DIR="$BACKUP_DIR" ./scripts/backup_postgres.sh

cat > /etc/cron.d/dirhunter-postgres-backup <<'CRON'
17 2 * * * root cd /opt/dirhunter_AI && PGHOST=127.0.0.1 PGPASSWORD=dirhunter DIRHUNTER_BACKUP_DIR=/var/backups/dirhunter ./scripts/backup_postgres.sh >/var/log/dirhunter-pg-backup.log 2>&1
CRON
chmod 0644 /etc/cron.d/dirhunter-postgres-backup

systemctl restart dirhunter-api dirhunter-worker dirhunter-slack dirhunter-ui

du -sh "$PROJECT_DIR/cron.log" "$PROJECT_DIR/results/html" "$BACKUP_DIR"
ls -1 "$BACKUP_DIR" | tail -3
systemctl is-active dirhunter-api dirhunter-worker dirhunter-slack dirhunter-ui

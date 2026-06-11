#!/usr/bin/env bash
set -Eeuo pipefail

BACKUP_DIR="${DIRHUNTER_BACKUP_DIR:-/var/backups/dirhunter}"
DB_NAME="${DIRHUNTER_DB_NAME:-dirhunter}"
DB_USER="${DIRHUNTER_DB_USER:-dirhunter}"
STAMP="$(date -u '+%Y%m%dT%H%M%SZ')"

mkdir -p "$BACKUP_DIR"
pg_dump -U "$DB_USER" -d "$DB_NAME" -Fc > "$BACKUP_DIR/${DB_NAME}_${STAMP}.dump"

find "$BACKUP_DIR" -name "${DB_NAME}_*.dump" -mtime +30 -delete

if [[ -n "${DIRHUNTER_BACKUP_S3_URI:-}" ]]; then
  aws s3 sync "$BACKUP_DIR" "$DIRHUNTER_BACKUP_S3_URI"
fi

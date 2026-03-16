#!/bin/bash
set -euo pipefail

DB_PATH="/home/ubuntu/misconfig-index/misconfig.db"
BACKUP_DIR="/home/ubuntu/backups"
KEEP_DAYS=3
DATE=$(date +%Y-%m-%d)
OUTFILE="${BACKUP_DIR}/misconfig_${DATE}.db"

mkdir -p "$BACKUP_DIR"
cp "$DB_PATH" "$OUTFILE"
echo "[$(date -u +%FT%TZ)] Backup saved: $OUTFILE"

# Prune backups older than KEEP_DAYS
find "$BACKUP_DIR" -name "misconfig_*.db" -mtime +${KEEP_DAYS} -delete
echo "[$(date -u +%FT%TZ)] Cleanup done (kept last ${KEEP_DAYS} days)"

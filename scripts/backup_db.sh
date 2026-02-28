#!/usr/bin/env bash
# backup_db.sh — PostgreSQL daily backup for Misconfig Index
#
# Dumps the database into /backups/misconfig-YYYY-MM-DD.sql.gz,
# keeps the last 30 days, and logs to /var/log/misconfig-backup.log.
#
# Install on the EC2 host:
#   sudo cp scripts/backup_db.sh /usr/local/bin/misconfig-backup.sh
#   sudo chmod +x /usr/local/bin/misconfig-backup.sh
#
# Add to root crontab (sudo crontab -e):
#   0 2 * * * /usr/local/bin/misconfig-backup.sh >> /var/log/misconfig-backup.log 2>&1
#
# Environment: expects POSTGRES_PASSWORD in /home/ubuntu/misconfig-index/.env
# (same file used by docker-compose)

set -euo pipefail

COMPOSE_DIR="/home/ubuntu/misconfig-index"
BACKUP_DIR="/backups/misconfig"
KEEP_DAYS=30
DB_NAME="misconfig_index"
DB_USER="misconfig"
DATE=$(date +%Y-%m-%d)
OUTFILE="${BACKUP_DIR}/misconfig-${DATE}.sql.gz"

echo "=== $(date) — Starting backup ==="

# Load POSTGRES_PASSWORD from the project's .env file
if [[ -f "${COMPOSE_DIR}/.env" ]]; then
    export PGPASSWORD=$(grep '^POSTGRES_PASSWORD=' "${COMPOSE_DIR}/.env" | cut -d= -f2)
fi

# Create backup directory if it doesn't exist
mkdir -p "${BACKUP_DIR}"

# Dump via Docker exec (no exposed port needed)
docker compose -f "${COMPOSE_DIR}/docker-compose.yml" exec -T db \
    pg_dump -U "${DB_USER}" "${DB_NAME}" \
    | gzip -9 > "${OUTFILE}"

SIZE=$(du -sh "${OUTFILE}" | cut -f1)
echo "Backup written: ${OUTFILE} (${SIZE})"

# Prune backups older than KEEP_DAYS
find "${BACKUP_DIR}" -name "misconfig-*.sql.gz" -mtime +${KEEP_DAYS} -delete
REMAINING=$(find "${BACKUP_DIR}" -name "misconfig-*.sql.gz" | wc -l)
echo "Backups retained: ${REMAINING} (last ${KEEP_DAYS} days)"
echo "=== Done ==="

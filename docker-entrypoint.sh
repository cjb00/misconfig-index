#!/bin/sh
# docker-entrypoint.sh
#
# Runs before the API server starts:
#   1. Waits for the database to be reachable (PostgreSQL only)
#   2. Initialises schema (create_all — idempotent)
#   3. Starts uvicorn with the configured worker count
set -e

DB_URL="${DATABASE_URL:-sqlite:///./data/misconfig_index.db}"

# ── Wait for PostgreSQL ───────────────────────────────────────────────────────
# If using SQLite, skip the wait entirely.
if echo "$DB_URL" | grep -q "^postgresql"; then
    echo "[entrypoint] Waiting for PostgreSQL…"
    # Extract host and port from DATABASE_URL
    # Expected format: postgresql://user:pass@host:port/db
    DB_HOST=$(echo "$DB_URL" | sed -E 's|.*@([^:/]+).*|\1|')
    DB_PORT=$(echo "$DB_URL" | sed -E 's|.*:([0-9]+)/.*|\1|')
    DB_PORT="${DB_PORT:-5432}"

    RETRIES=30
    until python -c "
import sys, socket
try:
    s = socket.create_connection(('${DB_HOST}', ${DB_PORT}), timeout=2)
    s.close()
    print('DB reachable')
except Exception as e:
    print(f'Not ready: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null; do
        RETRIES=$((RETRIES - 1))
        if [ "$RETRIES" -le 0 ]; then
            echo "[entrypoint] ERROR: PostgreSQL did not become ready in time." >&2
            exit 1
        fi
        echo "[entrypoint] PostgreSQL not ready — retrying in 2s… ($RETRIES attempts left)"
        sleep 2
    done
    echo "[entrypoint] PostgreSQL is ready."
fi

# ── Initialise schema ─────────────────────────────────────────────────────────
echo "[entrypoint] Initialising database schema…"
python -c "
from backend.deps import init_db
init_db()
print('[entrypoint] Schema ready.')
"

# ── Start the API server ──────────────────────────────────────────────────────
WORKERS="${API_WORKERS:-2}"
echo "[entrypoint] Starting uvicorn with ${WORKERS} worker(s)…"
exec uvicorn backend.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers "$WORKERS" \
    --proxy-headers \
    --forwarded-allow-ips="*"

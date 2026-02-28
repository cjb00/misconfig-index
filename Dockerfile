# ── Stage 1: build dependencies ───────────────────────────────────────────────
# Install all Python packages into /install so they can be copied cleanly.
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# System build deps (gcc for any C extensions, libpq-dev for psycopg2)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy packaging metadata first — Docker caches this pip layer separately
# from the source code, so editing .py files won't re-run pip install.
COPY pyproject.toml README.md* ./
# egg-info may not exist on a fresh checkout; create a stub so pip is happy
RUN mkdir -p misconfig_index.egg-info

RUN pip install --prefix=/install \
        "fastapi>=0.109.0" \
        "uvicorn[standard]>=0.24.0" \
        "sqlalchemy>=2.0.0" \
        "pydantic>=2.5.0" \
        "pydantic-settings>=2.0.0" \
        "python-dotenv>=1.0.0" \
        "psycopg2-binary>=2.9.0" \
        "requests>=2.31.0" \
        "alembic>=1.13.0" \
        "slowapi>=0.1.9" \
        "pyyaml>=6.0"


# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Runtime system deps only (libpq5 for psycopg2, git for GitHub scans)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 git && \
    rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN useradd -m -u 1000 appuser
WORKDIR /app

# Pull installed packages from builder stage
COPY --from=builder /install /usr/local

# Application source — separate COPY commands so editing one layer
# doesn't invalidate the others.
COPY backend/ ./backend/
COPY scanner/ ./scanner/
COPY scripts/ ./scripts/

# Writable data directory (for SQLite in dev; ignored when using PostgreSQL)
RUN mkdir -p /app/data && chown -R appuser:appuser /app

# Entrypoint: initialises the DB then starts uvicorn
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER appuser

EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]

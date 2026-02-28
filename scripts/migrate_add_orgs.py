"""
Migration: add organizations, api_keys tables and org_id to sources
====================================================================
Run once to upgrade an existing database to Phase 2 schema.
Safe to run multiple times (skips existing tables/columns).

Usage:
    python scripts/migrate_add_orgs.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from dotenv import load_dotenv
load_dotenv(ROOT_DIR / ".env")

from sqlalchemy import create_engine, text


def table_exists(conn, name: str) -> bool:
    row = conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name=:n"),
        {"n": name},
    ).fetchone()
    return row is not None


def column_exists(conn, table: str, column: str) -> bool:
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(r[1] == column for r in rows)


def main() -> None:
    db_url = os.getenv("DATABASE_URL", "sqlite:///./misconfig.db")
    print(f"Connecting to: {db_url}")
    engine = create_engine(db_url, future=True)

    with engine.begin() as conn:

        # 1. organizations
        if table_exists(conn, "organizations"):
            print("  ✓ organizations table already exists")
        else:
            conn.execute(text("""
                CREATE TABLE organizations (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    name       TEXT    NOT NULL,
                    slug       TEXT    NOT NULL UNIQUE,
                    created_at DATETIME DEFAULT (datetime('now'))
                )
            """))
            print("  + created organizations table")

        # 2. api_keys
        if table_exists(conn, "api_keys"):
            print("  ✓ api_keys table already exists")
        else:
            conn.execute(text("""
                CREATE TABLE api_keys (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id       INTEGER NOT NULL REFERENCES organizations(id),
                    name         TEXT    NOT NULL,
                    key_prefix   TEXT    NOT NULL,
                    key_hash     TEXT    NOT NULL UNIQUE,
                    is_active    INTEGER NOT NULL DEFAULT 1,
                    created_at   DATETIME DEFAULT (datetime('now')),
                    last_used_at DATETIME
                )
            """))
            conn.execute(text("CREATE INDEX ix_api_keys_key_hash ON api_keys (key_hash)"))
            print("  + created api_keys table")

        # 3. sources.org_id (nullable FK to organizations)
        if column_exists(conn, "sources", "org_id"):
            print("  ✓ sources.org_id already exists")
        else:
            conn.execute(text("ALTER TABLE sources ADD COLUMN org_id INTEGER REFERENCES organizations(id)"))
            print("  + added sources.org_id")

        # 4. scans: commit_sha, branch, scanner_version (Phase 2 ingest metadata)
        for col, col_type in [("commit_sha", "TEXT"), ("branch", "TEXT"), ("scanner_version", "TEXT")]:
            if column_exists(conn, "scans", col):
                print(f"  ✓ scans.{col} already exists")
            else:
                conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col} {col_type}"))
                print(f"  + added scans.{col}")

    print("\nMigration complete.")


if __name__ == "__main__":
    main()

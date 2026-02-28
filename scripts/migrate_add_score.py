"""
Migration: add score columns to the scans table
================================================
Run this once against an existing database to add the three Phase 1 columns:

    score                INTEGER   — 0–100 Misconfig Score
    score_breakdown      JSON      — {grade, <category>: score, ...}
    total_files_scanned  INTEGER   — files examined including clean ones

Safe to run multiple times (skips columns that already exist).

Usage:
    python scripts/migrate_add_score.py
    # or with a custom DB:
    DATABASE_URL=postgresql://... python scripts/migrate_add_score.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Make sure project root is on the path and .env is loaded
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from dotenv import load_dotenv          # noqa: E402
load_dotenv(ROOT_DIR / ".env")

from sqlalchemy import create_engine, text  # noqa: E402


def table_exists(conn, table: str) -> bool:
    result = conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name=:t"),
        {"t": table},
    )
    return result.fetchone() is not None


def column_exists(conn, table: str, column: str) -> bool:
    """Check whether a column exists in a SQLite table."""
    result = conn.execute(text(f"PRAGMA table_info({table})"))
    return any(row[1] == column for row in result)


NEW_COLUMNS = [
    ("score", "INTEGER"),
    ("score_breakdown", "JSON"),
    ("total_files_scanned", "INTEGER"),
]


def main() -> None:
    db_url = os.getenv("DATABASE_URL", "sqlite:///./misconfig.db")
    print(f"Connecting to: {db_url}")

    engine = create_engine(db_url, future=True)

    with engine.begin() as conn:
        if not table_exists(conn, "scans"):
            print("  scans table not found — run init_db.py first to create the schema.")
            return

        added = []
        for col_name, col_type in NEW_COLUMNS:
            if column_exists(conn, "scans", col_name):
                print(f"  ✓ scans.{col_name} already exists — skipping")
            else:
                conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col_name} {col_type}"))
                added.append(col_name)
                print(f"  + added scans.{col_name} ({col_type})")

    if added:
        print(f"\nMigration complete. Added: {', '.join(added)}")
    else:
        print("\nNo changes needed — schema already up to date.")


if __name__ == "__main__":
    main()

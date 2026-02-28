#!/usr/bin/env python3
"""
Seed historical scan data for the trend chart demo.
Creates ~12 synthetic scans spread over the last 60 days showing
a realistic security-posture improvement trajectory.

Usage:
    python -m scripts.seed_history
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

# ── path setup ──────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from dotenv import load_dotenv
load_dotenv(ROOT_DIR / ".env")

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT_DIR}/misconfig_index.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

from backend.models import Scan, Source, Organization

# ── historical scan data ─────────────────────────────────────────────────────
# Each entry: (days_ago, score, breakdown_dict)
# Simulates a team finding & fixing misconfigurations over 2 months.
HISTORY = [
    (60, 42, {"grade": "F", "networking": 35, "storage": 50, "identity": 40, "workload": 45}),
    (54, 48, {"grade": "F", "networking": 40, "storage": 55, "identity": 45, "workload": 50}),
    (48, 55, {"grade": "C", "networking": 48, "storage": 60, "identity": 52, "workload": 58}),
    (42, 61, {"grade": "C", "networking": 55, "storage": 65, "identity": 62, "workload": 63}),
    (36, 66, {"grade": "C", "networking": 60, "storage": 70, "identity": 66, "workload": 68}),
    (30, 71, {"grade": "C", "networking": 66, "storage": 75, "identity": 72, "workload": 72}),
    (24, 76, {"grade": "B", "networking": 72, "storage": 80, "identity": 78, "workload": 76}),
    (18, 80, {"grade": "B", "networking": 78, "storage": 83, "identity": 82, "workload": 78}),
    (12, 84, {"grade": "B", "networking": 82, "storage": 87, "identity": 85, "workload": 83}),
    (7,  88, {"grade": "B", "networking": 86, "storage": 90, "identity": 88, "workload": 87}),
    (3,  91, {"grade": "A", "networking": 90, "storage": 93, "identity": 92, "workload": 90}),
    (0,  94, {"grade": "A", "networking": 93, "storage": 96, "identity": 95, "workload": 92}),
]

BRANCHES = ["main", "main", "fix/s3-acl", "main", "main", "fix/network-policy",
            "main", "main", "feat/harden", "main", "main", "main"]

COMMITS = [
    "a1b2c3d", "e4f5a6b", "c7d8e9f", "a0b1c2d", "e3f4a5b",
    "c6d7e8f", "a9b0c1d", "e2f3a4b", "c5d6e7f", "a8b9c0d",
    "e1f2a3b", "c4d5e6f",
]


def _grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def main():
    db = SessionLocal()
    try:
        # Find or create a demo source (no org — simulates the local/public demo)
        source = db.query(Source).filter(
            Source.identifier == "demo/misconfig-index-demo"
        ).first()

        if source is None:
            source = Source(
                source_type="api",
                identifier="demo/misconfig-index-demo",
            )
            db.add(source)
            db.flush()
            print(f"Created demo source (id={source.id})")
        else:
            print(f"Using existing demo source (id={source.id})")

        now = datetime.utcnow()
        inserted = 0

        for i, (days_ago, score, breakdown) in enumerate(HISTORY):
            ts = now - timedelta(days=days_ago)

            # Don't re-insert if a scan already exists at this timestamp (within 1 hour)
            existing = db.query(Scan).filter(
                Scan.source_id == source.id,
                Scan.started_at >= ts - timedelta(hours=1),
                Scan.started_at <= ts + timedelta(hours=1),
            ).first()
            if existing:
                print(f"  Skipping day -{days_ago}: scan already exists (id={existing.id})")
                continue

            scan = Scan(
                source_id=source.id,
                started_at=ts,
                finished_at=ts + timedelta(seconds=12),
                status="success",
                branch=BRANCHES[i % len(BRANCHES)],
                commit_sha=COMMITS[i % len(COMMITS)],
                scanner_version="0.2.0",
                score=score,
                score_breakdown=breakdown,
                total_files_scanned=18,
            )
            db.add(scan)
            inserted += 1

        db.commit()
        print(f"\nSeeded {inserted} historical scans for source '{source.identifier}'.")
        print("Run the API and load /reports/history to verify.")

    finally:
        db.close()


if __name__ == "__main__":
    main()

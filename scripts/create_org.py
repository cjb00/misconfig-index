"""
Bootstrap an organization and API key for local development / testing.

Usage:
    python scripts/create_org.py --name "Acme Corp" --slug "acme"
    python scripts/create_org.py --name "Acme Corp" --slug "acme" --key-name "CI Pipeline"
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from dotenv import load_dotenv
load_dotenv(ROOT_DIR / ".env")

from sqlalchemy.orm import Session
from backend.deps import SessionLocal
from backend import crud, models


def main() -> None:
    parser = argparse.ArgumentParser(description="Create an org and API key")
    parser.add_argument("--name", required=True, help="Organization display name")
    parser.add_argument("--slug", required=True, help="URL-safe slug (lowercase, hyphens OK)")
    parser.add_argument("--key-name", default="default", help="Name for the API key (default: 'default')")
    args = parser.parse_args()

    db: Session = SessionLocal()
    try:
        # Create org (or fetch existing)
        existing = db.query(models.Organization).filter(models.Organization.slug == args.slug).first()
        if existing:
            org = existing
            print(f"Org '{org.name}' (id={org.id}) already exists — adding key.")
        else:
            org = models.Organization(name=args.name, slug=args.slug)
            db.add(org)
            db.commit()
            db.refresh(org)
            print(f"Created org '{org.name}' (id={org.id})")

        # Create API key
        db_key, raw_key = crud.create_api_key(db, org_id=org.id, name=args.key_name)

        print()
        print("=" * 56)
        print(f"  Organization : {org.name}  (id={org.id})")
        print(f"  Key name     : {db_key.name}")
        print(f"  Key prefix   : {db_key.key_prefix}...")
        print(f"  API key      : {raw_key}")
        print("=" * 56)
        print()
        print("Store the API key securely — it will not be shown again.")
        print()
        print("Usage:")
        print(f'  curl -X POST http://localhost:8000/v1/ingest \\')
        print(f'    -H "X-API-Key: {raw_key}" \\')
        print(f'    -H "Content-Type: application/json" \\')
        print(f'    -d \'{{...}}\'')

    finally:
        db.close()


if __name__ == "__main__":
    main()

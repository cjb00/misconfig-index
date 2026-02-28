from __future__ import annotations

import sys
from pathlib import Path
import os

from sqlalchemy.orm import Session
from sqlalchemy import create_engine

# ensure imports work inside Docker (/app) and locally
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.deps import Base  # noqa: E402
from backend import models     # noqa: E402
from scanner.rules import terraform, kubernetes  # noqa: E402  # imported so rules are registered


DEFAULT_RULES = [
    {
        "id": "TF_OPEN_SG_0_0_0_0",
        "category": "terraform",
        "title": "Security Group open to 0.0.0.0/0",
        "description": "Ingress rule allows 0.0.0.0/0, exposing service to internet.",
        "severity": "high",
        "tags": ["network", "exposure"],
    },
    {
        "id": "K8S_PRIVILEGED_CONTAINER",
        "category": "kubernetes",
        "title": "Privileged Kubernetes Container",
        "description": "Container runs with privileged: true.",
        "severity": "critical",
        "tags": ["k8s", "privilege"],
    },
]


def main() -> None:
    db_url = os.getenv("DATABASE_URL", "sqlite:///./data/misconfig_index.db")
    print(f"Connecting to database: {db_url}")

    engine = create_engine(db_url, future=True)
    Base.metadata.create_all(bind=engine)

    with Session(engine) as db:
        existing_ids = {r.id for r in db.query(models.MisconfigRule).all()}
        new_rules = [r for r in DEFAULT_RULES if r["id"] not in existing_ids]

        for rule in new_rules:
            db_rule = models.MisconfigRule(**rule)
            db.add(db_rule)

        db.commit()

    print(f"Seeded {len(new_rules)} rules.")


if __name__ == "__main__":
    main()
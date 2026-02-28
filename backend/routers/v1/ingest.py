"""
POST /v1/ingest — submit scan results from CI/CD or the CLI.

Authentication: X-API-Key header (key issued via POST /v1/orgs/{id}/keys).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ... import crud, schemas
from ...auth import get_current_org
from ...deps import get_db
from ...models import Organization

router = APIRouter()


@router.post("", response_model=schemas.IngestResponse, status_code=201)
def ingest(
    payload: schemas.IngestPayload,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
):
    """
    Submit findings from a scanner run. The server computes the Misconfig Score
    and persists the scan linked to the authenticated organization.

    **Finding rule_ids** must match the built-in rule registry. Unknown rule_ids
    are skipped and returned in `skipped_rule_ids` for transparency.
    """
    return crud.ingest_scan(db, org=org, payload=payload)

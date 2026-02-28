"""
GET /v1/repos                   — list repos for the authenticated org
GET /v1/repos/{id}/score        — latest score for a specific repo
GET /v1/repos/{id}/history      — score history for a repo (trend data)
GET /v1/repos/{id}/findings     — findings from the latest scan

Authentication: X-API-Key header.
"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ... import crud, schemas
from ...auth import get_current_org
from ...deps import get_db
from ...models import Organization

router = APIRouter()


@router.get("", response_model=List[schemas.RepoSummary])
def list_repos(
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
):
    """List all repos (sources) for the authenticated org with their latest scores."""
    return crud.get_repos(db, org)


@router.get("/{source_id}/score", response_model=schemas.ScanScore)
def repo_score(
    source_id: int,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
):
    """Return the latest Misconfig Score for a specific repo."""
    from ...models import Scan, Source

    source = (
        db.query(Source)
        .filter(Source.id == source_id, Source.org_id == org.id)
        .first()
    )
    if not source:
        raise HTTPException(status_code=404, detail="Repo not found")

    latest = (
        db.query(Scan)
        .filter(Scan.source_id == source_id)
        .order_by(Scan.started_at.desc())
        .first()
    )
    if not latest:
        raise HTTPException(status_code=404, detail="No scans found for this repo")

    result = crud.get_scan_score(db, latest.id)
    return result


@router.get("/{source_id}/history", response_model=List[schemas.ScanHistoryEntry])
def repo_history(
    source_id: int,
    limit: int = Query(default=30, ge=1, le=100),
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
):
    """
    Score history for a repo — chronological list of scan scores.
    Use this to render trend charts and track improvement over time.
    """
    result = crud.get_repo_history(db, source_id=source_id, org_id=org.id, limit=limit)
    if result is None:
        raise HTTPException(status_code=404, detail="Repo not found")
    return result


@router.get("/{source_id}/findings", response_model=List[schemas.RepoFinding])
def repo_findings(
    source_id: int,
    limit: int = 200,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
):
    """Return findings from the latest scan for a repo."""
    rows = crud.get_repo_findings(db, source_id=source_id, org_id=org.id, limit=limit)
    if rows is None:
        raise HTTPException(status_code=404, detail="Repo not found")
    return rows

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import crud, schemas
from ..deps import get_db

router = APIRouter()


@router.get("/{scan_id}/score", response_model=schemas.ScanScore)
def scan_score(scan_id: int, db: Session = Depends(get_db)):
    """
    Return the Misconfig Score and per-category breakdown for a specific scan.

    GET /scans/{scan_id}/score
    """
    result = crud.get_scan_score(db, scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return result

from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import crud, schemas
from ..deps import get_db

router = APIRouter()


@router.get("/", response_model=List[schemas.Finding])
def list_findings(
    rule_id: Optional[str] = Query(default=None),
    file_type: Optional[str] = Query(default=None),
    source_id: Optional[int] = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    findings = crud.get_findings(
        db,
        rule_id=rule_id,
        file_type=file_type,
        source_id=source_id,
        skip=skip,
        limit=limit,
    )
    return findings

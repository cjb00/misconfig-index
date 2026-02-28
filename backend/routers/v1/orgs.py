"""
POST /v1/orgs          — create an organization
POST /v1/orgs/{id}/keys — create an API key for an org
GET  /v1/orgs/{id}/keys — list API keys for an org
"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ... import crud, schemas
from ...deps import get_db

router = APIRouter()


@router.post("", response_model=schemas.OrgResponse, status_code=201)
def create_org(body: schemas.OrgCreate, db: Session = Depends(get_db)):
    """Create a new organization. Slug must be unique and lowercase alphanumeric."""
    return crud.create_org(db, name=body.name, slug=body.slug)


@router.post("/{org_id}/keys", response_model=schemas.ApiKeyResponse, status_code=201)
def create_key(org_id: int, body: schemas.ApiKeyCreate, db: Session = Depends(get_db)):
    """
    Create an API key for the org.
    The full key is returned **once** in the response — store it securely.
    """
    org = crud.get_org_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    db_key, raw_key = crud.create_api_key(db, org_id=org.id, name=body.name)

    return schemas.ApiKeyResponse(
        id=db_key.id,
        name=db_key.name,
        key_prefix=db_key.key_prefix,
        is_active=db_key.is_active,
        created_at=db_key.created_at,
        last_used_at=db_key.last_used_at,
        key=raw_key,  # only here, never again
    )


@router.get("/{org_id}/keys", response_model=List[schemas.ApiKeyResponse])
def list_keys(org_id: int, db: Session = Depends(get_db)):
    """List API keys for an org (prefixes only — full keys are never returned after creation)."""
    org = crud.get_org_by_id(db, org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org.api_keys

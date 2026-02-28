"""
API key authentication for the v1 API.

Keys are formatted as:  mi_<32 random hex chars>
Stored as:              key_prefix (first 10 chars) + sha256(full_key)

The full key is returned exactly once at creation time and never stored.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from .deps import get_db
from .models import ApiKey, Organization

_header = APIKeyHeader(name="X-API-Key", auto_error=False)

KEY_PREFIX = "mi_"
KEY_BYTES = 16  # 32 hex chars


def generate_key() -> str:
    """Return a new random API key string."""
    return KEY_PREFIX + secrets.token_hex(KEY_BYTES)


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def get_current_org(
    raw_key: Optional[str] = Security(_header),
    db: Session = Depends(get_db),
) -> Organization:
    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header is required",
        )

    key_hash = hash_key(raw_key)
    db_key: Optional[ApiKey] = (
        db.query(ApiKey)
        .filter(ApiKey.key_hash == key_hash, ApiKey.is_active.is_(True))
        .first()
    )

    if db_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
        )

    db_key.last_used_at = datetime.utcnow()
    db.commit()

    return db_key.org

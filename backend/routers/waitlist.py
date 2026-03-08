from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..deps import get_db
from ..models import WaitlistEntry
from ..ratelimit import limiter

router = APIRouter()

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class WaitlistRequest(BaseModel):
    email: str


@router.post("", status_code=201)
@limiter.limit("5/hour")
def join_waitlist(request: Request, body: WaitlistRequest, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail="Invalid email address.")
    entry = WaitlistEntry(email=email)
    db.add(entry)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Already on the list — treat as success so we don't leak existence
    return {"ok": True}

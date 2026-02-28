"""
GET /v1/benchmark — authenticated industry benchmark comparison.

Authentication: X-API-Key header (key issued via POST /v1/orgs/{id}/keys).
Returns the org's score vs. the industry average, percentile ranking,
per-category comparison, and the global top misconfigs list.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ... import crud, schemas
from ...auth import get_current_org
from ...deps import get_db
from ...models import Organization
from ...ratelimit import limiter

router = APIRouter()


@router.get("", response_model=schemas.OrgBenchmarkStats)
@limiter.limit("30/minute")
def org_benchmark(
    request: Request,
    org: Organization = Depends(get_current_org),
    db: Session = Depends(get_db),
):
    """
    Return the authenticated org's Misconfig Score compared to the industry
    benchmark across all organisations in the last 90 days.

    Includes:
    - `your_score` and `your_grade` — the org's most recent scan
    - `your_percentile` — percentage of repos scoring ≤ your score
    - `category_comparison` — per-category industry avg vs your score
    - `grade_distribution` — count of repos per grade (A–F)
    - `top_misconfigs` — the most-common failing rules across all repos
    """
    data = crud.get_org_benchmark(db, org=org)
    return schemas.OrgBenchmarkStats(**data)

"""
GET /badge/{org_slug}/{repo_path:path}

Returns a shields.io-style SVG badge showing the latest Misconfig Score.
No authentication required — designed for embedding in README files.

Example:
  ![Misconfig Score](https://api.misconfig.dev/badge/acme/github.com/acme/infra)

Cache-Control: max-age=300 (5 min) so badges stay fresh without hammering the DB.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from ..deps import get_db
from ..models import Organization, Scan, Source
from ..ratelimit import limiter

router = APIRouter()

# Grade → hex color
_GRADE_COLOR = {
    "A": "#22c55e",
    "B": "#84cc16",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}
_UNKNOWN_COLOR = "#64748b"


def _svg(score: int | None, grade: str | None) -> str:
    label = "misconfig score"
    value = f"{score} {grade}" if score is not None else "no data"
    color = _GRADE_COLOR.get(grade or "", _UNKNOWN_COLOR)

    # Fixed-width layout (shields.io proportions, monospace estimate)
    label_w = 108   # px for label text area
    value_w = 56    # px for value text area
    total_w = label_w + value_w
    height = 20

    # Text x-centres (scaled ×10 for sub-pixel via transform="scale(.1)")
    label_cx = (label_w // 2) * 10
    value_cx = (label_w + value_w // 2) * 10

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{height}" role="img" aria-label="{label}: {value}">
  <title>{label}: {value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_w}" height="{height}" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_w}" height="{height}" fill="#555"/>
    <rect x="{label_w}" width="{value_w}" height="{height}" fill="{color}"/>
    <rect width="{total_w}" height="{height}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">
    <text x="{label_cx}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{(label_w-10)*10}" lengthAdjust="spacing">{label}</text>
    <text x="{label_cx}" y="140" transform="scale(.1)" textLength="{(label_w-10)*10}" lengthAdjust="spacing">{label}</text>
    <text x="{value_cx}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{(value_w-10)*10}" lengthAdjust="spacing">{value}</text>
    <text x="{value_cx}" y="140" transform="scale(.1)" textLength="{(value_w-10)*10}" lengthAdjust="spacing">{value}</text>
  </g>
</svg>"""


@router.get("/{org_slug}/{repo_path:path}")
@limiter.limit("120/minute")
def badge(request: Request, org_slug: str, repo_path: str, db: Session = Depends(get_db)):
    """
    Return an SVG badge for the latest Misconfig Score of a repo.
    org_slug  — the org's URL slug (e.g. 'acme')
    repo_path — full repo identifier (e.g. 'github.com/acme/infra')
    """
    score, grade = None, None

    org = db.query(Organization).filter(Organization.slug == org_slug).first()
    if org:
        source = (
            db.query(Source)
            .filter(Source.org_id == org.id, Source.identifier == repo_path)
            .first()
        )
        if source:
            latest = (
                db.query(Scan)
                .filter(Scan.source_id == source.id, Scan.score.isnot(None))
                .order_by(Scan.started_at.desc())
                .first()
            )
            if latest:
                score = latest.score
                grade = (latest.score_breakdown or {}).get("grade")

    svg = _svg(score, grade)
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={
            "Cache-Control": "max-age=300, s-maxage=300",
            "Content-Type": "image/svg+xml",
        },
    )

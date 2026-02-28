import io
import re
import tempfile
import urllib.request
import zipfile
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from .. import crud, schemas
from ..deps import get_db
from ..ratelimit import limiter

router = APIRouter()


@router.get("/latest", response_model=schemas.ScanReport)
@limiter.limit("60/minute")
def latest_report(request: Request, db: Session = Depends(get_db)):
    """
    Return the latest scan summary including the Misconfig Score.
    Falls back to a zero-state response if no scans exist.
    """
    return crud.get_latest_summary(db)


@router.get("/history", response_model=List[schemas.ScanHistoryEntry])
@limiter.limit("60/minute")
def public_history(
    request: Request,
    limit: int = Query(default=30, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """
    Public score history across all recent scans — used by the dashboard
    trend chart. No authentication required.
    """
    return crud.get_public_history(db, limit=limit)


@router.get("/benchmark", response_model=schemas.PublicBenchmarkStats)
@limiter.limit("30/minute")
def public_benchmark(request: Request, db: Session = Depends(get_db)):
    """
    Aggregated industry benchmark statistics across all repos in the last 90 days.
    No authentication required — used by the public dashboard benchmark panel.

    Includes grade distribution, per-category averages, and top misconfigs.
    """
    data = crud.get_public_benchmark(db)
    return schemas.PublicBenchmarkStats(**data)


# ── Quick scan (public GitHub URL) ────────────────────────────────────────────

# Patterns excluded by default when scanning via the web UI — avoids inflating
# scores with intentionally bad example/fixture code.
_DEFAULT_EXCLUDE = ("examples", "example", "tests", "test", "fixtures", "fixture", ".github")

# GitHub archive URL for the default branch HEAD (works on all public repos)
_GH_ZIP_TMPL = "https://github.com/{repo}/archive/HEAD.zip"

# Maximum ZIP size accepted (50 MB) — prevents abuse with giant repos
_MAX_ZIP_BYTES = 50 * 1024 * 1024


@router.post("/scan", response_model=schemas.QuickScanResult)
@limiter.limit("5/minute")
def quick_scan(request: Request, body: schemas.QuickScanRequest) -> Any:
    """
    Download a public GitHub repo and return its Misconfig Score.

    Accepts URLs in any of these forms:
      - https://github.com/owner/repo
      - github.com/owner/repo
      - owner/repo

    Rate limited to 5 requests/minute per IP.  Only public repos are supported.
    """
    # ── Parse owner/repo ──────────────────────────────────────────────────────
    url = body.url.strip().rstrip("/")
    m = re.search(
        r"(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)$",
        url,
    ) or re.fullmatch(r"([A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)", url)
    if not m:
        raise HTTPException(
            status_code=422,
            detail="Invalid GitHub URL. Expected format: github.com/owner/repo",
        )
    repo_path = m.group(1)

    # ── Download ZIP archive ──────────────────────────────────────────────────
    zip_url = _GH_ZIP_TMPL.format(repo=repo_path)
    try:
        req = urllib.request.Request(
            zip_url,
            headers={"User-Agent": "misconfig-index/0.2.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            # Read up to _MAX_ZIP_BYTES + 1 to detect oversized archives
            zip_data = resp.read(_MAX_ZIP_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(404, f"Repository '{repo_path}' not found or is private.")
        raise HTTPException(502, f"GitHub returned HTTP {exc.code} for {repo_path}.")
    except Exception as exc:
        raise HTTPException(502, f"Could not download repository: {exc}")

    if len(zip_data) > _MAX_ZIP_BYTES:
        raise HTTPException(413, "Repository archive exceeds 50 MB limit.")

    # ── Extract & scan ────────────────────────────────────────────────────────
    from scanner.cli import scan_path, _rule_registry
    from scanner.scoring import compute_score

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                zf.extractall(tmpdir)
        except zipfile.BadZipFile:
            raise HTTPException(502, "Downloaded archive is not a valid ZIP file.")

        scan_result = scan_path(tmpdir, exclude=_DEFAULT_EXCLUDE)

    all_findings = [f for fr in scan_result.files for f in fr.findings]
    score_result = compute_score(all_findings, scan_result.total_files_scanned)
    reg = _rule_registry()

    def _strip_root(p: str) -> str:
        """Remove the top-level archive directory (e.g. 'repo-HEAD/') from paths."""
        parts = p.replace("\\", "/").split("/", 1)
        return parts[1] if len(parts) == 2 else p

    top_findings = [
        schemas.QuickScanFinding(
            rule_id=f.rule_id,
            file=_strip_root(fr.path),
            line_start=f.line_start,
            snippet=f.snippet,
            remediation=reg[f.rule_id].remediation if f.rule_id in reg else "",
        )
        for fr in scan_result.files
        for f in fr.findings
    ][:50]

    return schemas.QuickScanResult(
        repo=repo_path,
        score=score_result.score,
        grade=score_result.grade,
        breakdown=score_result.breakdown,
        total_files_scanned=scan_result.total_files_scanned,
        total_findings=len(all_findings),
        findings=top_findings,
    )

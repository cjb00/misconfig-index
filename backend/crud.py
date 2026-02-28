from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from .auth import generate_key, hash_key
from .models import ApiKey, File, Finding, MisconfigRule, Organization, Scan, Source


# ---------------------------------------------------------------------------
# Phase 1: reports
# ---------------------------------------------------------------------------

def get_findings(
    db: Session,
    rule_id: Optional[str] = None,
    file_type: Optional[str] = None,
    source_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
) -> List[Finding]:
    query = db.query(Finding).join(File, Finding.file_id == File.id).join(Scan)
    if rule_id:
        query = query.filter(Finding.rule_id == rule_id)
    if file_type:
        query = query.filter(File.file_type == file_type)
    if source_id:
        query = query.filter(Scan.source_id == source_id)
    return query.offset(skip).limit(limit).all()


def get_latest_summary(db: Session) -> Dict[str, Any]:
    """Aggregated summary for the latest scan, including score."""
    latest_scan = db.query(Scan).order_by(Scan.started_at.desc()).first()
    if not latest_scan:
        return {
            "total_findings": 0,
            "top_5_rules": [],
            "counts_by_severity": {},
            "score": None,
            "grade": None,
            "score_breakdown": None,
            "total_files_scanned": None,
            "generated_at": datetime.utcnow().isoformat(),
        }

    total_findings = (
        db.query(func.count(Finding.id))
        .filter(Finding.scan_id == latest_scan.id)
        .scalar() or 0
    )

    severity_counts = (
        db.query(MisconfigRule.severity, func.count(Finding.id))
        .join(MisconfigRule, MisconfigRule.id == Finding.rule_id)
        .filter(Finding.scan_id == latest_scan.id)
        .group_by(MisconfigRule.severity)
        .all()
    )

    top_rules = (
        db.query(Finding.rule_id, func.count(Finding.id).label("cnt"))
        .filter(Finding.scan_id == latest_scan.id)
        .group_by(Finding.rule_id)
        .order_by(func.count(Finding.id).desc())
        .limit(5)
        .all()
    )

    breakdown_copy = {
        k: v for k, v in (latest_scan.score_breakdown or {}).items() if k != "grade"
    }
    grade = (latest_scan.score_breakdown or {}).get("grade")

    return {
        "total_findings": total_findings,
        "top_5_rules": [{"rule_id": r.rule_id, "count": r.cnt} for r in top_rules],
        "counts_by_severity": {s: c for s, c in severity_counts},
        "score": latest_scan.score,
        "grade": grade,
        "score_breakdown": breakdown_copy or None,
        "total_files_scanned": latest_scan.total_files_scanned,
        "generated_at": datetime.utcnow().isoformat(),
    }


def get_scan_score(db: Session, scan_id: int) -> Optional[Dict[str, Any]]:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return None
    breakdown = {k: v for k, v in (scan.score_breakdown or {}).items() if k != "grade"}
    grade = (scan.score_breakdown or {}).get("grade")
    return {
        "scan_id": scan.id,
        "score": scan.score,
        "grade": grade,
        "breakdown": breakdown or None,
        "total_files_scanned": scan.total_files_scanned,
        "scanned_at": scan.started_at,
    }


# ---------------------------------------------------------------------------
# Phase 2: organizations & API keys
# ---------------------------------------------------------------------------

def create_org(db: Session, name: str, slug: str) -> Organization:
    from fastapi import HTTPException
    if db.query(Organization).filter(Organization.slug == slug).first():
        raise HTTPException(status_code=409, detail=f"Slug '{slug}' is already taken")
    org = Organization(name=name, slug=slug)
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


def create_api_key(db: Session, org_id: int, name: str) -> Tuple[ApiKey, str]:
    """
    Create a new API key. Returns (ORM object, raw key string).
    The raw key is returned once and never stored — only its sha256 hash is persisted.
    """
    raw = generate_key()
    db_key = ApiKey(
        org_id=org_id,
        name=name,
        key_prefix=raw[:10],
        key_hash=hash_key(raw),
        is_active=True,
    )
    db.add(db_key)
    db.commit()
    db.refresh(db_key)
    return db_key, raw


def get_org_by_id(db: Session, org_id: int) -> Optional[Organization]:
    return db.query(Organization).filter(Organization.id == org_id).first()


# ---------------------------------------------------------------------------
# Phase 2: ingest
# ---------------------------------------------------------------------------

def _sync_rules(db: Session) -> None:
    """
    Upsert all scanner rules into misconfig_rules so FK constraints are
    satisfied when ingesting findings from external sources.
    """
    from scanner.rules import cloudformation, dockerfile, kubernetes, terraform

    all_rules = (
        terraform.get_rules()
        + kubernetes.get_rules()
        + cloudformation.get_rules()
        + dockerfile.get_rules()
    )
    existing_ids = {row[0] for row in db.query(MisconfigRule.id).all()}
    for rule in all_rules:
        if rule.id not in existing_ids:
            db.add(MisconfigRule(
                id=rule.id,
                category=rule.category,
                title=rule.title,
                description=rule.description,
                severity=str(rule.severity),
                tags=getattr(rule, "tags", []),
            ))
    db.commit()


def ingest_scan(db: Session, org: Organization, payload) -> Dict[str, Any]:
    """
    Persist an ingest payload, compute score, return result dict.
    Findings with unrecognised rule_ids are skipped and reported back.
    """
    from scanner.rules.base import Finding as ScannerFinding
    from scanner.scoring import compute_score

    _sync_rules(db)

    known_ids = {row[0] for row in db.query(MisconfigRule.id).all()}
    valid = [f for f in payload.findings if f.rule_id in known_ids]
    skipped = list({f.rule_id for f in payload.findings if f.rule_id not in known_ids})

    # Get or create Source scoped to this org + repo identifier
    source = (
        db.query(Source)
        .filter(Source.org_id == org.id, Source.identifier == payload.repo)
        .first()
    )
    if source is None:
        source = Source(org_id=org.id, source_type="api", identifier=payload.repo)
        db.add(source)
        db.flush()

    # Compute score
    scanner_findings = [
        ScannerFinding(
            rule_id=f.rule_id,
            line_start=f.line_start,
            line_end=f.line_end,
            snippet=f.snippet,
        )
        for f in valid
    ]
    score_result = compute_score(scanner_findings, payload.total_files_scanned)

    # Persist Scan
    scan = Scan(
        source_id=source.id,
        status="success",
        commit_sha=payload.commit_sha,
        branch=payload.branch,
        scanner_version=payload.scanner_version,
        score=score_result.score,
        score_breakdown={"grade": score_result.grade, **score_result.breakdown},
        total_files_scanned=payload.total_files_scanned,
        finished_at=datetime.utcnow(),
    )
    db.add(scan)
    db.flush()

    # Group by file, persist File + Finding rows
    by_file: Dict[Tuple[str, str], List] = {}
    for f in valid:
        by_file.setdefault((f.file_path, f.file_type), []).append(f)

    for (file_path, file_type), file_findings in by_file.items():
        file_obj = File(source_id=source.id, path=file_path, file_type=file_type)
        db.add(file_obj)
        db.flush()
        for f in file_findings:
            db.add(Finding(
                scan_id=scan.id,
                file_id=file_obj.id,
                rule_id=f.rule_id,
                line_start=f.line_start,
                line_end=f.line_end,
                snippet=f.snippet,
            ))

    db.commit()

    return {
        "scan_id": scan.id,
        "repo": payload.repo,
        "score": score_result.score,
        "grade": score_result.grade,
        "score_breakdown": score_result.breakdown,
        "total_findings": len(valid),
        "skipped_rule_ids": skipped,
        "message": "Scan ingested successfully",
    }


# ---------------------------------------------------------------------------
# Phase 2: repo queries
# ---------------------------------------------------------------------------

def get_repos(db: Session, org: Organization) -> List[Dict[str, Any]]:
    sources = db.query(Source).filter(Source.org_id == org.id).all()
    rows = []
    for src in sources:
        latest = (
            db.query(Scan)
            .filter(Scan.source_id == src.id)
            .order_by(Scan.started_at.desc())
            .first()
        )
        total = db.query(func.count(Scan.id)).filter(Scan.source_id == src.id).scalar() or 0
        grade = (latest.score_breakdown or {}).get("grade") if latest else None
        rows.append({
            "id": src.id,
            "identifier": src.identifier,
            "latest_score": latest.score if latest else None,
            "latest_grade": grade,
            "total_scans": total,
            "last_scanned_at": latest.started_at if latest else None,
        })
    return rows


def get_repo_findings(
    db: Session, source_id: int, org_id: int, limit: int = 200
) -> List[Dict[str, Any]]:
    """Findings from the latest scan for a repo, scoped to org."""
    source = (
        db.query(Source)
        .filter(Source.id == source_id, Source.org_id == org_id)
        .first()
    )
    if not source:
        return []

    latest = (
        db.query(Scan)
        .filter(Scan.source_id == source_id)
        .order_by(Scan.started_at.desc())
        .first()
    )
    if not latest:
        return []

    rows = (
        db.query(Finding, File)
        .join(File, Finding.file_id == File.id)
        .filter(Finding.scan_id == latest.id)
        .limit(limit)
        .all()
    )
    return [
        {
            "rule_id": f.rule_id,
            "file_path": file.path,
            "file_type": file.file_type,
            "line_start": f.line_start,
            "snippet": f.snippet,
            "detected_at": f.detected_at,
        }
        for f, file in rows
    ]


# ---------------------------------------------------------------------------
# Phase 3: trend tracking
# ---------------------------------------------------------------------------

def _scan_to_history_entry(db: Session, scan: Scan) -> Dict[str, Any]:
    count = (
        db.query(func.count(Finding.id))
        .filter(Finding.scan_id == scan.id)
        .scalar() or 0
    )
    return {
        "scan_id": scan.id,
        "score": scan.score,
        "grade": (scan.score_breakdown or {}).get("grade"),
        "total_findings": count,
        "scanned_at": scan.started_at,
        "branch": getattr(scan, "branch", None),
        "commit_sha": getattr(scan, "commit_sha", None),
    }


def get_repo_history(
    db: Session, source_id: int, org_id: int, limit: int = 30
) -> Optional[List[Dict[str, Any]]]:
    """Score history for a specific repo (authenticated). Returns None if not found."""
    source = (
        db.query(Source)
        .filter(Source.id == source_id, Source.org_id == org_id)
        .first()
    )
    if not source:
        return None

    scans = (
        db.query(Scan)
        .filter(Scan.source_id == source_id, Scan.score.isnot(None))
        .order_by(Scan.started_at.desc())
        .limit(limit)
        .all()
    )
    return list(reversed([_scan_to_history_entry(db, s) for s in scans]))


def get_public_history(db: Session, limit: int = 30) -> List[Dict[str, Any]]:
    """Score history across all scans for the public dashboard (no auth)."""
    scans = (
        db.query(Scan)
        .filter(Scan.score.isnot(None))
        .order_by(Scan.started_at.desc())
        .limit(limit)
        .all()
    )
    return list(reversed([_scan_to_history_entry(db, s) for s in scans]))


# ---------------------------------------------------------------------------
# Phase 4: benchmarking
# ---------------------------------------------------------------------------

def get_public_benchmark(db: Session, days: int = 90) -> Optional[Dict[str, Any]]:
    """
    Aggregate anonymised benchmark stats across all recent scans.
    No org-specific data — safe to expose publicly.
    """
    cutoff = datetime.utcnow() - timedelta(days=days)

    scans = (
        db.query(Scan)
        .filter(Scan.score.isnot(None), Scan.started_at >= cutoff)
        .all()
    )
    if not scans:
        return None

    scores = [s.score for s in scans]
    avg_score = int(sum(scores) / len(scores))

    # Grade distribution
    grade_dist: Dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for scan in scans:
        grade = (scan.score_breakdown or {}).get("grade", "F")
        if grade in grade_dist:
            grade_dist[grade] += 1

    # Per-category averages (extracted from JSON breakdown)
    cat_totals: Dict[str, List[int]] = {}
    for scan in scans:
        for k, v in (scan.score_breakdown or {}).items():
            if k == "grade" or not isinstance(v, (int, float)):
                continue
            cat_totals.setdefault(k, []).append(int(v))

    category_averages = {
        cat: int(sum(vals) / len(vals))
        for cat, vals in cat_totals.items()
    }

    # Most common misconfigs across all recent scans
    # Chunk scan_ids to stay within SQLite's variable limit
    scan_ids = [s.id for s in scans]
    rule_counter: Dict[str, int] = {}
    for i in range(0, len(scan_ids), 450):
        chunk = scan_ids[i : i + 450]
        rows = (
            db.query(Finding.rule_id, func.count(Finding.id).label("cnt"))
            .filter(Finding.scan_id.in_(chunk))
            .group_by(Finding.rule_id)
            .all()
        )
        for rule_id, cnt in rows:
            rule_counter[rule_id] = rule_counter.get(rule_id, 0) + cnt

    top_misconfigs = sorted(rule_counter.items(), key=lambda x: -x[1])[:10]
    unique_sources = len({s.source_id for s in scans})

    return {
        "total_repos": unique_sources,
        "total_scans": len(scans),
        "industry_avg_score": avg_score,
        "grade_distribution": grade_dist,
        "category_averages": category_averages,
        "top_misconfigs": [{"rule_id": r, "count": c} for r, c in top_misconfigs],
        "computed_at": datetime.utcnow().isoformat(),
    }


def get_org_benchmark(db: Session, org: Organization) -> Optional[Dict[str, Any]]:
    """
    Public benchmark stats extended with the org's own percentile ranking.
    Authenticated endpoint only.
    """
    public = get_public_benchmark(db)
    if not public:
        return None

    # Org's most recent scored scan (across all their repos)
    latest_scan = (
        db.query(Scan)
        .join(Source, Scan.source_id == Source.id)
        .filter(Source.org_id == org.id, Scan.score.isnot(None))
        .order_by(Scan.started_at.desc())
        .first()
    )

    if not latest_scan:
        return {
            **public,
            "your_score": None,
            "your_grade": None,
            "your_percentile": None,
            "category_comparison": [],
        }

    your_score = latest_scan.score
    your_grade = (latest_scan.score_breakdown or {}).get("grade")

    # Percentile: fraction of all recent scans with score ≤ your_score
    cutoff = datetime.utcnow() - timedelta(days=90)
    all_scores = [
        row[0]
        for row in db.query(Scan.score).filter(
            Scan.score.isnot(None), Scan.started_at >= cutoff
        ).all()
    ]
    percentile = int(
        sum(1 for s in all_scores if s <= your_score) / len(all_scores) * 100
    ) if all_scores else 0

    # Per-category comparison: your score vs industry average
    your_breakdown = {
        k: int(v)
        for k, v in (latest_scan.score_breakdown or {}).items()
        if k != "grade" and isinstance(v, (int, float))
    }
    category_comparison = [
        {
            "category": cat,
            "industry_avg": avg,
            "your_score": your_breakdown.get(cat),
        }
        for cat, avg in public["category_averages"].items()
    ]

    return {
        **public,
        "your_score": your_score,
        "your_grade": your_grade,
        "your_percentile": percentile,
        "category_comparison": category_comparison,
    }

from __future__ import annotations

from datetime import datetime, date
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Phase 1 schemas
# ---------------------------------------------------------------------------

class MisconfigRule(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    category: str
    title: str
    description: str
    severity: str
    tags: Optional[List[str]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class Finding(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    file_id: int
    rule_id: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    snippet: str
    extra: Optional[Dict[str, Any]] = None
    detected_at: datetime


class DailySummary(BaseModel):
    date: date
    total_findings: int
    by_severity: Dict[str, int]
    top_rules: List[Dict[str, Any]]


class ScanReport(BaseModel):
    """Response for GET /reports/latest."""

    total_findings: int
    top_5_rules: List[Dict[str, Any]]
    counts_by_severity: Dict[str, int]
    score: Optional[int] = None
    grade: Optional[str] = None
    score_breakdown: Optional[Dict[str, int]] = None
    total_files_scanned: Optional[int] = None
    generated_at: str


class ScanScore(BaseModel):
    """Response for GET /scans/{scan_id}/score."""

    scan_id: int
    score: Optional[int]
    grade: Optional[str]
    breakdown: Optional[Dict[str, int]]
    total_files_scanned: Optional[int]
    scanned_at: Optional[datetime]


# ---------------------------------------------------------------------------
# Phase 2: Organizations & API keys
# ---------------------------------------------------------------------------

class OrgCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=50, pattern=r"^[a-z0-9-]+$")


class OrgResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    created_at: datetime


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class ApiKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    key_prefix: str
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime] = None
    key: Optional[str] = None  # only populated at creation time


# ---------------------------------------------------------------------------
# Phase 2: Ingest
# ---------------------------------------------------------------------------

class IngestFinding(BaseModel):
    """A single finding in an ingest payload."""

    rule_id: str
    file_path: str
    file_type: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    snippet: str = ""


class IngestPayload(BaseModel):
    """Body for POST /v1/ingest."""

    repo: str = Field(..., description="Repo identifier, e.g. github.com/org/repo")
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    findings: List[IngestFinding]
    total_files_scanned: int = Field(..., ge=0)
    scanner_version: Optional[str] = None


class IngestResponse(BaseModel):
    """Response from POST /v1/ingest."""

    scan_id: int
    repo: str
    score: int
    grade: str
    score_breakdown: Dict[str, int]
    total_findings: int
    skipped_rule_ids: List[str]
    message: str


# ---------------------------------------------------------------------------
# Phase 2: Repos
# ---------------------------------------------------------------------------

class RepoSummary(BaseModel):
    """One row in GET /v1/repos."""

    id: int
    identifier: str
    latest_score: Optional[int]
    latest_grade: Optional[str]
    total_scans: int
    last_scanned_at: Optional[datetime]


class RepoFinding(BaseModel):
    """Flattened finding for GET /v1/repos/{id}/findings."""

    rule_id: str
    file_path: str
    file_type: str
    line_start: Optional[int]
    snippet: str
    detected_at: datetime


# ---------------------------------------------------------------------------
# Phase 3: Trend tracking
# ---------------------------------------------------------------------------

class ScanHistoryEntry(BaseModel):
    """One data point in a score history series."""

    scan_id: int
    score: Optional[int]
    grade: Optional[str]
    total_findings: int
    scanned_at: datetime
    branch: Optional[str] = None
    commit_sha: Optional[str] = None


# ---------------------------------------------------------------------------
# Phase 4: Industry benchmarking
# ---------------------------------------------------------------------------

class GradeDistribution(BaseModel):
    """Count of repos/scans at each grade level."""
    A: int = 0
    B: int = 0
    C: int = 0
    D: int = 0
    F: int = 0


class TopMisconfig(BaseModel):
    """A rule that appears most frequently across all scans."""
    rule_id: str
    count: int


class CategoryComparison(BaseModel):
    """Your score vs the industry average for a single category."""
    category: str
    industry_avg: int
    your_score: Optional[int] = None


class PublicBenchmarkStats(BaseModel):
    """
    Anonymised aggregate stats across all recent scans.
    Returned by GET /reports/benchmark — no authentication required.
    """
    total_repos: int
    total_scans: int
    industry_avg_score: int
    grade_distribution: GradeDistribution
    category_averages: Dict[str, int]
    top_misconfigs: List[TopMisconfig]
    computed_at: str


class OrgBenchmarkStats(PublicBenchmarkStats):
    """
    Public benchmark stats extended with org-specific percentile data.
    Returned by GET /v1/benchmark — requires authentication.
    """
    your_score: Optional[int] = None
    your_grade: Optional[str] = None
    your_percentile: Optional[int] = None   # you score better than X% of repos
    category_comparison: List[CategoryComparison] = []


# ── Quick scan (POST /reports/scan) ───────────────────────────────────────────

class QuickScanRequest(BaseModel):
    url: str  # e.g. "github.com/owner/repo" or full https URL


class QuickScanFinding(BaseModel):
    rule_id: str
    file: str
    line_start: Optional[int]
    snippet: str
    remediation: str


class QuickScanResult(BaseModel):
    repo: str
    score: int
    grade: str
    breakdown: Dict[str, int]
    total_files_scanned: int
    total_findings: int
    findings: List[QuickScanFinding]  # top 50

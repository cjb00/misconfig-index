"""
Misconfig Index — Scoring Engine
=================================
Converts a list of raw scanner findings into a 0–100 score and per-category
breakdown. The score reflects security posture: 100 = no findings, 0 = severe.

Severity weights
----------------
    critical = 10  |  high = 5  |  medium = 2  |  low = 1

Normalization formula
---------------------
Previous formula divided penalty by *total_files*, which gave large repos a
near-linear size advantage — a 100-file repo could absorb 10× as many findings
as a 10-file repo before losing the same number of points.

The new formula uses sqrt normalization:

    normalised = (total_penalty / sqrt(files)) * SQRT_SCALE

sqrt(files) grows slowly, so size still provides *some* credit for clean code,
but doesn't hide systemic issues in large codebases.

Calibration (SQRT_SCALE = 3.0):
    1 high finding,  10 files → 95/100 (A)   ← minor, isolated issue
    5 high findings, 10 files → 76/100 (B)   ← noticeable cluster
   33 findings (mixed high/crit), 98 files   → ~49/100 (D)
   10+ criticals across any repo             → 0–40 (F)

Grades: A ≥ 90 | B ≥ 75 | C ≥ 60 | D ≥ 40 | F < 40
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional

from .rules import cloudformation, dockerfile, kubernetes, terraform
from .rules.base import Finding, Severity

# ---------------------------------------------------------------------------
# Severity → numeric weight
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: Dict[str, int] = {
    Severity.critical: 10,
    Severity.high: 5,
    Severity.medium: 2,
    Severity.low: 1,
}

# sqrt normalization scale factor (see module docstring for calibration)
_SQRT_SCALE = 3.0


# ---------------------------------------------------------------------------
# Rule registry — maps rule_id → (severity_value, category)
# ---------------------------------------------------------------------------

def _build_registry() -> Dict[str, tuple[str, str]]:
    all_rules = (
        terraform.get_rules()
        + kubernetes.get_rules()
        + cloudformation.get_rules()
        + dockerfile.get_rules()
    )
    # Use .value to get the plain string ("high", "critical", etc.) rather than
    # str(enum_member) which returns "Severity.high" and breaks SEVERITY_WEIGHTS lookup.
    return {rule.id: (rule.severity.value, rule.category) for rule in all_rules}


_REGISTRY: Optional[Dict[str, tuple[str, str]]] = None


def _registry() -> Dict[str, tuple[str, str]]:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = _build_registry()
    return _REGISTRY


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScoreResult:
    score: int                          # 0–100
    grade: str                          # A / B / C / D / F
    breakdown: Dict[str, int]           # {category: score}
    total_penalty: int                  # raw sum of severity weights
    total_files_scanned: int


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _penalty_to_score(penalty: int, files: int) -> int:
    """Convert a weighted penalty to a 0–100 score using sqrt normalization."""
    normalised = (penalty / math.sqrt(max(files, 1))) * _SQRT_SCALE
    return max(0, min(100, round(100 - normalised)))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_score(findings: List[Finding], total_files_scanned: int) -> ScoreResult:
    """
    Compute an overall score and per-category breakdown.

    Parameters
    ----------
    findings:
        Raw Finding objects from the scanner (each has a .rule_id).
    total_files_scanned:
        Number of IaC files examined, including clean files.

    Returns
    -------
    ScoreResult
    """
    reg = _registry()
    files = max(total_files_scanned, 1)

    # Enrich findings with severity + category via registry lookup
    by_category: Dict[str, List[int]] = {}  # category -> [weights]
    total_penalty = 0

    for f in findings:
        entry = reg.get(f.rule_id)
        if entry is None:
            # Unknown rule — treat as medium
            weight = SEVERITY_WEIGHTS[Severity.medium]
            category = "other"
        else:
            severity, category = entry
            weight = SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS[Severity.medium])

        total_penalty += weight
        by_category.setdefault(category, []).append(weight)

    overall = _penalty_to_score(total_penalty, files)

    breakdown: Dict[str, int] = {
        cat: _penalty_to_score(sum(weights), files)
        for cat, weights in by_category.items()
    }

    return ScoreResult(
        score=overall,
        grade=_grade(overall),
        breakdown=breakdown,
        total_penalty=total_penalty,
        total_files_scanned=files,
    )

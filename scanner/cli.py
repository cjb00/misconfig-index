import argparse
import fnmatch
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from backend.deps import SessionLocal
from backend import models

from .rules import base as rule_base
from .rules import terraform, kubernetes, cloudformation, dockerfile
from .scoring import compute_score


@dataclass
class FileScanResult:
    path: str
    file_type: str
    findings: List[rule_base.Finding] = field(default_factory=list)


@dataclass
class ScanResult:
    root_path: str
    files: List[FileScanResult]
    total_files_scanned: int = 0  # all IaC files examined, including clean ones


_RULE_REGISTRY: Optional[Dict[str, rule_base.Rule]] = None


def _rule_registry() -> Dict[str, rule_base.Rule]:
    """Lazy singleton: maps rule_id -> Rule instance."""
    global _RULE_REGISTRY
    if _RULE_REGISTRY is None:
        all_rules = (
            terraform.get_rules()
            + kubernetes.get_rules()
            + cloudformation.get_rules()
            + dockerfile.get_rules()
        )
        _RULE_REGISTRY = {r.id: r for r in all_rules}
    return _RULE_REGISTRY


def _load_exclude_patterns(root_path: str, extra: Sequence[str] = ()) -> List[str]:
    """
    Combine patterns from a .misconfigignore file at root_path with any
    extra patterns passed via --exclude.  Each pattern is a glob that is
    matched against path components (e.g. "examples", "*/test/*").
    """
    patterns: List[str] = list(extra)
    ignore_file = os.path.join(root_path, ".misconfigignore")
    if os.path.isfile(ignore_file):
        with open(ignore_file, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    return patterns


def _is_excluded(full_path: str, root_path: str, patterns: List[str]) -> bool:
    """
    Return True if full_path should be skipped based on exclude patterns.

    Each pattern is matched against:
      - every individual path component of the relative path
      - the full relative path
    so a pattern like "examples" skips any file inside an examples/ directory,
    and "*/test/*" matches a relative path segment.
    """
    if not patterns:
        return False
    rel = os.path.relpath(full_path, root_path)
    parts = rel.replace("\\", "/").split("/")
    for pattern in patterns:
        if fnmatch.fnmatch(rel.replace("\\", "/"), pattern):
            return True
        for part in parts:
            if fnmatch.fnmatch(part, pattern):
                return True
    return False


def detect_file_type(filename: str, content: str) -> str:
    """Very simple file type detection based on extension and content."""
    lname = filename.lower()

    if lname.endswith(".tf"):
        return "terraform"
    if lname.endswith((".yaml", ".yml")):
        # naive: treat all YAML as kubernetes for now
        return "kubernetes"
    if "AWSTemplateFormatVersion" in content:
        return "cloudformation"
    if os.path.basename(lname) == "dockerfile":
        return "dockerfile"

    return "unknown"


def get_rules_for_type(file_type: str) -> List[rule_base.Rule]:
    if file_type == "terraform":
        return terraform.get_rules()
    if file_type == "kubernetes":
        return kubernetes.get_rules()
    if file_type == "cloudformation":
        return cloudformation.get_rules()
    if file_type == "dockerfile":
        return dockerfile.get_rules()
    return []


def scan_path(root_path: str, exclude: Sequence[str] = ()) -> ScanResult:
    """Walk a directory, scan files, and collect findings in memory.

    Parameters
    ----------
    root_path:
        Directory to scan recursively.
    exclude:
        Extra glob patterns to skip in addition to any .misconfigignore file
        found at the root of root_path.
    """
    file_results: List[FileScanResult] = []
    total_files_scanned = 0
    patterns = _load_exclude_patterns(root_path, exclude)

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune excluded directories in-place so os.walk won't descend into them
        dirnames[:] = [
            d for d in dirnames
            if not _is_excluded(os.path.join(dirpath, d), root_path, patterns)
        ]

        for name in filenames:
            full_path = os.path.join(dirpath, name)

            if _is_excluded(full_path, root_path, patterns):
                continue

            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            file_type = detect_file_type(name, content)
            rules = get_rules_for_type(file_type)
            if not rules:
                continue

            # Count every file that has applicable rules (clean or not)
            total_files_scanned += 1

            findings: List[rule_base.Finding] = []
            for rule in rules:
                findings.extend(rule.match(content, full_path))

            if findings:
                file_results.append(
                    FileScanResult(
                        path=os.path.relpath(full_path, root_path),
                        file_type=file_type,
                        findings=findings,
                    )
                )

    return ScanResult(
        root_path=root_path,
        files=file_results,
        total_files_scanned=total_files_scanned,
    )


def persist_to_db(scan_result: ScanResult) -> None:
    """Persist scan result into the database using SQLAlchemy models."""
    db = SessionLocal()
    try:
        # 1) Get or create Source
        source_identifier = f"local:{os.path.abspath(scan_result.root_path)}"
        source = (
            db.query(models.Source)
            .filter(models.Source.identifier == source_identifier)
            .one_or_none()
        )
        if source is None:
            source = models.Source(
                source_type="local_fs",
                identifier=source_identifier,
                meta=None,
            )
            db.add(source)
            db.flush()  # assigns source.id

        # 2) Compute score before creating Scan
        all_findings = [f for fr in scan_result.files for f in fr.findings]
        score_result = compute_score(all_findings, scan_result.total_files_scanned)

        scan = models.Scan(
            source_id=source.id,
            status="success",
            notes=None,
            score=score_result.score,
            score_breakdown={"grade": score_result.grade, **score_result.breakdown},
            total_files_scanned=scan_result.total_files_scanned,
        )
        db.add(scan)
        db.flush()  # assigns scan.id

        # 3) Create File + Finding rows
        for file_result in scan_result.files:
            file_obj = models.File(
                source_id=source.id,
                path=file_result.path,
                file_type=file_result.file_type,
                hash=None,  # could compute sha256 later
            )
            db.add(file_obj)
            db.flush()  # assigns file_obj.id

            for finding in file_result.findings:
                db_finding = models.Finding(
                    scan_id=scan.id,
                    file_id=file_obj.id,
                    rule_id=finding.rule_id,
                    line_start=finding.line_start,
                    line_end=finding.line_end,
                    snippet=finding.snippet,
                    extra=finding.extra,
                )
                db.add(db_finding)

        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def summarize(scan_result: ScanResult) -> None:
    """Print a CLI summary."""
    files_by_type: Dict[str, int] = {}
    findings_by_rule: Dict[str, int] = {}
    findings_per_file: Dict[str, int] = {}

    for fr in scan_result.files:
        files_by_type[fr.file_type] = files_by_type.get(fr.file_type, 0) + 1
        findings_per_file[fr.path] = findings_per_file.get(fr.path, 0) + len(fr.findings)
        for f in fr.findings:
            findings_by_rule[f.rule_id] = findings_by_rule.get(f.rule_id, 0) + 1

    all_findings = [f for fr in scan_result.files for f in fr.findings]
    score_result = compute_score(all_findings, scan_result.total_files_scanned)

    grade_colors = {"A": "\033[92m", "B": "\033[32m", "C": "\033[93m", "D": "\033[33m", "F": "\033[91m"}
    reset = "\033[0m"
    color = grade_colors.get(score_result.grade, "")

    print(f"\nScanned path: {scan_result.root_path}")
    print(f"Files scanned: {scan_result.total_files_scanned}  |  Files with findings: {len(scan_result.files)}")
    print(f"\n{'─'*40}")
    print(f"  Misconfig Score: {color}{score_result.score}/100  (Grade {score_result.grade}){reset}")
    print(f"{'─'*40}")

    if score_result.breakdown:
        print("  Category breakdown:")
        for cat, cat_score in sorted(score_result.breakdown.items()):
            bar = "█" * (cat_score // 10) + "░" * (10 - cat_score // 10)
            print(f"    {cat:<14} {bar}  {cat_score}/100")

    print(f"{'─'*40}\n")
    print(f"Files by type:  {files_by_type}")

    registry = _rule_registry()
    print("Findings by rule:")
    for rule_id, count in sorted(findings_by_rule.items(), key=lambda x: -x[1]):
        rule = registry.get(rule_id)
        severity = rule.severity.value.upper() if rule else "UNKNOWN"
        print(f"  [{severity}] {rule_id}: {count}")
        if rule and rule.remediation:
            print(f"    → {rule.remediation}")

    print("\nTop files by findings:")
    sorted_files: List[Tuple[str, int]] = sorted(
        findings_per_file.items(), key=lambda x: x[1], reverse=True
    )
    for path, count in sorted_files[:10]:
        print(f"  {path}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Misconfig Index scanner CLI")
    parser.add_argument(
        "scan",
        nargs="?",
        help="Scan a path for misconfigurations (usage: scan --path ./foo)",
    )
    parser.add_argument(
        "--path",
        dest="path",
        required=False,
        help="Path to scan (directory)",
    )
    args = parser.parse_args()

    if args.scan != "scan" or not args.path:
        parser.print_help()
        return

    root_path = args.path
    scan_result = scan_path(root_path)
    summarize(scan_result)
    persist_to_db(scan_result)


if __name__ == "__main__":
    main()
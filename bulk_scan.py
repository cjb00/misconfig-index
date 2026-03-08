#!/usr/bin/env python3
"""
bulk_scan.py — Locally scan a list of public GitHub repos using the
misconfig-index scanner and save results to a text file.

Each repo is cloned with `git clone --depth 1`, scanned in-process,
then the clone is deleted. No network calls to the API — runs entirely
on your machine. No repo size limits.

Usage:
    python bulk_scan.py repos.txt
    python bulk_scan.py repos.txt --output results.txt
    python bulk_scan.py repos.txt --output results.txt --json results.json
    python bulk_scan.py repos.txt --skip-errors --workers 4

Input file format (repos.txt):
    One GitHub repo URL per line.
    Lines starting with # are comments and are skipped.
    Accepts any of these formats:
        github.com/owner/repo
        https://github.com/owner/repo
        owner/repo

Requirements:
    - Python 3.8+
    - git (must be on PATH)
    - misconfig-index package installed  OR  run from the project root
      (the scanner/ directory must be importable)
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any


# ── Import the scanner ────────────────────────────────────────────────────────
# Works whether misconfig-index is `pip install`-ed or you're running from
# the project root where scanner/ lives.

def _import_scanner():
    try:
        from scanner.scanner import scan_file
        from scanner.loader import walk_files
        from scanner.scoring import compute_score
        from scanner.rules import terraform, kubernetes, cloudformation, dockerfile
        return scan_file, walk_files, compute_score, [terraform, kubernetes, cloudformation, dockerfile]
    except ImportError:
        # Add the directory containing this script to sys.path and retry
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        try:
            from scanner.scanner import scan_file
            from scanner.loader import walk_files
            from scanner.scoring import compute_score
            from scanner.rules import terraform, kubernetes, cloudformation, dockerfile
            return scan_file, walk_files, compute_score, [terraform, kubernetes, cloudformation, dockerfile]
        except ImportError:
            print(
                "Error: could not import the scanner.\n"
                "  Run this script from the misconfig-index project root, or\n"
                "  install the package first:  pip install misconfig-index",
                file=sys.stderr,
            )
            sys.exit(1)

scan_file, walk_files, compute_score, _rule_modules = _import_scanner()


# ── Config ────────────────────────────────────────────────────────────────────

# Directories excluded from scanning (same set the quick-scan API uses)
EXCLUDE_DIRS = frozenset({
    "examples", "example", "tests", "test", "fixtures", "fixture",
    ".github", "vendor", "node_modules", ".terraform",
    "docs", "doc", "demo",     # avoid scanning documentation examples
    "wrappers",                 # auto-generated wrapper modules (terraform-aws-modules pattern)
})

GIT_CLONE_TIMEOUT = 600   # seconds — large repos can be slow to clone
SCAN_TIMEOUT      = 60    # seconds — scanning should be fast

# Grade colours (ANSI)
GRADE_COLOR = {"A": "\033[92m", "B": "\033[32m", "C": "\033[33m", "D": "\033[33m", "F": "\033[31m"}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
NO_COLOR = False


# ── Utility ───────────────────────────────────────────────────────────────────

def colorize(text: str, code: str) -> str:
    return text if NO_COLOR else f"{code}{text}{RESET}"


def bar(value: int, width: int = 20) -> str:
    filled = int(round((value / 100) * width))
    return "█" * filled + "░" * (width - filled)


def fmt(n: Any) -> str:
    if n is None:
        return "—"
    return f"{n:,}" if isinstance(n, int) else str(n)


DIVIDER = "=" * 72
THIN    = "─" * 72


def read_urls(path: Path) -> list[str]:
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def normalise_url(raw: str) -> tuple[str, str]:
    """
    Return (clone_url, display_name) for a GitHub repo URL in any format.
    """
    url = raw.strip()
    # Strip trailing slashes and .git suffixes
    url = url.rstrip("/").removesuffix(".git")

    if url.startswith(("https://", "http://")):
        # Full URL — use as-is for clone, extract owner/repo for display
        parts = url.split("github.com/", 1)
        display = parts[1] if len(parts) == 2 else url
        clone_url = url
    elif url.startswith("github.com/"):
        display = url[len("github.com/"):]
        clone_url = f"https://{url}"
    elif "/" in url:
        # owner/repo shorthand
        display = url
        clone_url = f"https://github.com/{url}"
    else:
        display = url
        clone_url = f"https://github.com/{url}"

    return clone_url, display


# ── Remediation registry ──────────────────────────────────────────────────────

def _build_remediation_map() -> dict[str, str]:
    """Build rule_id → remediation lookup from all loaded rules."""
    result = {}
    for mod in _rule_modules:
        for rule in mod.get_rules():
            rem = getattr(rule, "remediation", "")
            if rem:
                result[rule.id] = rem
    return result

_REMEDIATION: dict[str, str] | None = None

def remediation_for(rule_id: str) -> str:
    global _REMEDIATION
    if _REMEDIATION is None:
        _REMEDIATION = _build_remediation_map()
    return _REMEDIATION.get(rule_id, "")


# ── Scan a single repo ────────────────────────────────────────────────────────

def _is_excluded(path: Path, root: Path) -> bool:
    """Return True if any component of the path relative to root is excluded."""
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return False
    return any(part in EXCLUDE_DIRS for part in rel_parts)


def scan_directory(root: Path) -> tuple[list, int]:
    """
    Walk root, scan all IaC files (skipping excluded dirs), and return
    (findings, total_iac_files_scanned).
    """
    all_findings = []
    total_files = 0

    for path, content in walk_files(root):
        if _is_excluded(path, root):
            continue

        file_type, findings = scan_file(path.name, content)
        if file_type == "unknown":
            continue

        total_files += 1
        # Attach filename to each finding's extra dict for display
        for f in findings:
            f.extra["_file"] = str(path.relative_to(root))
        all_findings.extend(findings)

    return all_findings, total_files


def scan_repo(clone_url: str, display: str) -> dict:
    """
    Clone a repo, scan it locally, return a result dict.
    Raises on clone failure or scan error.
    """
    tmpdir = tempfile.mkdtemp(prefix="misconfig_")
    try:
        # ── 1. Clone ───────────────────────────────────────────────────────
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", clone_url, tmpdir],
            capture_output=True,
            text=True,
            timeout=GIT_CLONE_TIMEOUT,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            raise RuntimeError(f"git clone failed: {stderr[:300]}")

        # ── 2. Scan ────────────────────────────────────────────────────────
        root = Path(tmpdir)
        findings, total_files = scan_directory(root)

        # ── 3. Score ───────────────────────────────────────────────────────
        score_result = compute_score(findings, total_files)

        # ── 4. Build result dict ───────────────────────────────────────────
        finding_dicts = []
        for f in findings:
            finding_dicts.append({
                "rule_id":    f.rule_id,
                "file":       f.extra.get("_file", ""),
                "line_start": f.line_start,
                "snippet":    f.snippet[:200],
                "remediation": remediation_for(f.rule_id),
            })

        return {
            "repo":                 display,
            "clone_url":            clone_url,
            "score":                score_result.score,
            "grade":                score_result.grade,
            "breakdown":            score_result.breakdown,
            "total_files_scanned":  total_files,
            "total_findings":       len(findings),
            "findings":             finding_dicts,
        }

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── Formatting ────────────────────────────────────────────────────────────────

def format_detail_block(r: dict) -> str:
    score     = r.get("score", "—")
    grade     = r.get("grade", "?")
    files     = r.get("total_files_scanned", "—")
    total_f   = r.get("total_findings", 0)
    breakdown = r.get("breakdown") or {}
    findings  = r.get("findings") or []

    lines = [
        THIN,
        f"  {r['repo']}",
        THIN,
        f"  Score:  {fmt(score)} / 100   Grade: {grade}",
        f"  Files:  {fmt(files)} IaC files scanned   |   {fmt(total_f)} finding(s)",
    ]

    if breakdown:
        lines.append("")
        lines.append("  Category breakdown:")
        for cat, s in sorted(breakdown.items(), key=lambda kv: kv[1]):
            lines.append(f"    {cat:<22} {bar(s, 18)} {s:3d}")

    if findings:
        lines.append("")
        shown = findings[:15]
        lines.append(f"  Findings ({len(shown)} of {total_f} shown):")
        for f in shown:
            loc = f.get("file", "")
            if f.get("line_start"):
                loc = f"{loc}:{f['line_start']}"
            rule = f.get("rule_id", "")
            lines.append(f"    [{rule}]  {loc}")
            snip = f.get("snippet", "").strip()
            if snip:
                lines.append(f"      {snip[:80]}")
            rem = f.get("remediation", "")
            if rem:
                short = rem[:72] + ("…" if len(rem) > 72 else "")
                lines.append(f"      → {short}")
    elif total_f == 0:
        lines.append("")
        lines.append("  ✓ No findings — clean!")

    lines.append("")
    return "\n".join(lines)


def format_summary(results: list[dict], errors: list[dict], total: int) -> str:
    scores = [r["score"] for r in results if r.get("score") is not None]
    avg = sum(scores) / len(scores) if scores else 0

    grade_dist: dict[str, int] = {}
    for r in results:
        g = r.get("grade", "?")
        grade_dist[g] = grade_dist.get(g, 0) + 1

    lines = [
        "",
        DIVIDER,
        "  SUMMARY",
        DIVIDER,
        f"  Repos in list:  {total}",
        f"  Successful:     {len(results)}",
        f"  Errors:         {len(errors)}",
        f"  Average score:  {avg:.1f} / 100",
        "",
        "  Grade distribution:",
    ]

    max_count = max(grade_dist.values(), default=1)
    for grade in ["A", "B", "C", "D", "F"]:
        count = grade_dist.get(grade, 0)
        if count == 0:
            continue
        blen = max(1, int((count / max_count) * 24))
        lines.append(f"    Grade {grade}:  {count:3d}  {'■' * blen}")

    if results:
        sorted_r = sorted(results, key=lambda r: (r.get("score") or 0))
        lines += ["", "  Lowest scoring:"]
        for r in sorted_r[:5]:
            lines.append(f"    {r.get('score','—'):>3} ({r.get('grade','?')})  {r.get('repo','')}")
        lines += ["", "  Highest scoring:"]
        for r in reversed(sorted_r[-5:]):
            lines.append(f"    {r.get('score','—'):>3} ({r.get('grade','?')})  {r.get('repo','')}")

    if errors:
        lines += ["", "  Errors:"]
        for e in errors:
            lines.append(f"    ✗  {e['url']}")
            lines.append(f"       {e['error'][:120]}")

    lines += ["", DIVIDER, ""]
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    global NO_COLOR

    parser = argparse.ArgumentParser(
        description="Locally scan public GitHub repos using the misconfig-index scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("input", help="Text file with one GitHub URL per line")
    parser.add_argument("--output", "-o",
                        help="Output text file (default: scan_results_<timestamp>.txt)")
    parser.add_argument("--json", "-j", dest="json_output",
                        help="Also save raw JSON to this file")
    parser.add_argument("--skip-errors", action="store_true",
                        help="Continue after errors instead of stopping")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colour in terminal output")
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        NO_COLOR = True

    # ── Preflight check ─────────────────────────────────────────────────────

    if not shutil.which("git"):
        print("Error: 'git' not found on PATH — required for cloning repos.", file=sys.stderr)
        sys.exit(1)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: '{input_path}' not found.", file=sys.stderr)
        sys.exit(1)

    urls = read_urls(input_path)
    if not urls:
        print("Error: no URLs found in input file.", file=sys.stderr)
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = Path(args.output or f"scan_results_{timestamp}.txt")
    json_path = Path(args.json_output) if args.json_output else None

    print(colorize("\n  Misconfig Index — Local Bulk Scanner", BOLD))
    print(f"  {len(urls)} repo(s) to scan → {output_path}")
    print(f"  Scans run entirely on your machine (git clone + local scanner)")
    print()

    results: list[dict] = []
    errors:  list[dict] = []

    with open(output_path, "w", encoding="utf-8") as out:
        header = [
            "Misconfig Index — Local Bulk Scan Results",
            f"Generated:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Input file: {input_path}",
            f"Repos:      {len(urls)}",
            "",
            DIVIDER,
            "  SCAN LOG",
            DIVIDER,
            "",
        ]
        out.write("\n".join(header) + "\n")
        out.flush()

        for i, raw_url in enumerate(urls, 1):
            clone_url, display = normalise_url(raw_url)
            prefix = f"[{i:>3}/{len(urls)}]"
            short  = display[:50]

            print(f"  {prefix} {short:<52}", end="", flush=True)
            t0 = time.monotonic()

            try:
                result = scan_repo(clone_url, display)
                elapsed = time.monotonic() - t0
                results.append(result)

                grade   = result["grade"]
                score   = result["score"]
                total_f = result["total_findings"]
                col     = GRADE_COLOR.get(grade, "")

                print(
                    f"\r  {prefix} {short:<52}"
                    f"  {colorize(f'Grade {grade}', col)}  "
                    f"{score}/100  "
                    f"{colorize(f'{fmt(total_f)} finding(s)', DIM)}  "
                    f"{colorize(f'({elapsed:.0f}s)', DIM)}"
                )

                out.write(
                    f"{prefix} {display}  →  {grade}  {score}/100  "
                    f"{fmt(total_f)} finding(s)  ({elapsed:.0f}s)\n"
                )
                out.flush()

            except Exception as exc:
                elapsed = time.monotonic() - t0
                msg = str(exc)
                errors.append({"url": raw_url, "error": msg})

                print(
                    f"\r  {prefix} {short:<52}"
                    f"  {colorize('ERROR', BOLD)}  {msg[:60]}"
                )
                out.write(f"{prefix} {display}  →  ERROR: {msg[:200]}\n")
                out.flush()

                if not args.skip_errors:
                    print(
                        f"\n  Stopped after error. Use --skip-errors to continue.\n"
                        f"  Partial results saved to {output_path}\n",
                        file=sys.stderr,
                    )
                    break

        # ── Write detailed results ──────────────────────────────────────────

        out.write(f"\n\n{DIVIDER}\n  DETAILED RESULTS\n{DIVIDER}\n\n")
        for r in results:
            out.write(format_detail_block(r))
        for e in errors:
            out.write(f"{THIN}\n  {e['url']}\n{THIN}\n  ERROR: {e['error']}\n\n")

        # ── Write summary ───────────────────────────────────────────────────

        summary = format_summary(results, errors, len(urls))
        out.write(summary)

    print()
    print(summary)
    print(f"  Results saved to: {colorize(str(output_path), BOLD)}")

    if json_path:
        payload = {
            "generated_at": datetime.now().isoformat(),
            "input_file":   str(input_path),
            "total_urls":   len(urls),
            "results":      results,
            "errors":       errors,
        }
        json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"  JSON saved to:    {colorize(str(json_path), BOLD)}")

    print()
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()

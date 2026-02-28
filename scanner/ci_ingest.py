"""
Misconfig Index — CI Ingest
============================
Scans a local IaC path and posts results to the Misconfig Index API.
Designed to run in CI/CD pipelines (GitHub Actions, GitLab CI, etc.).

Usage:
    python -m scanner.ci_ingest \\
        --path ./infra \\
        --repo github.com/myorg/myrepo \\
        --branch main \\
        --commit abc123 \\
        --min-score 60

Environment variables (preferred for secrets):
    MISCONFIG_API_KEY   API key issued via POST /v1/orgs/{id}/keys
    MISCONFIG_API_URL   Base URL (default: https://api.misconfig.dev)

Exit codes:
    0  success (score ≥ min-score, or no threshold set)
    1  score below --min-score threshold
    2  scan or network error
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scanner.cli import scan_path

DEFAULT_API_URL = "https://api.misconfig.dev"

GRADE_COLORS = {"A": "\033[92m", "B": "\033[32m", "C": "\033[93m", "D": "\033[33m", "F": "\033[91m"}
RESET = "\033[0m"


def _post_json(url: str, payload: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "User-Agent": "misconfig-index-ci/0.3.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"API error {e.code}: {body}") from e


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan IaC and post results to Misconfig Index",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--path", required=True, help="Directory to scan")
    parser.add_argument("--repo", required=True, help="Repo identifier, e.g. github.com/org/repo")
    parser.add_argument("--branch", default=None, help="Git branch name")
    parser.add_argument("--commit", default=None, help="Git commit SHA")
    parser.add_argument("--api-url", default=None, help="API base URL (overrides MISCONFIG_API_URL)")
    parser.add_argument("--min-score", type=int, default=None,
                        help="Fail (exit 1) if score is below this threshold")
    parser.add_argument("--dry-run", action="store_true",
                        help="Scan and print results without posting to the API")
    args = parser.parse_args()

    api_key = os.getenv("MISCONFIG_API_KEY", "")
    api_url = args.api_url or os.getenv("MISCONFIG_API_URL", DEFAULT_API_URL)
    api_url = api_url.rstrip("/")

    if not args.dry_run and not api_key:
        print("ERROR: MISCONFIG_API_KEY environment variable is required.", file=sys.stderr)
        sys.exit(2)

    # ── Scan ──────────────────────────────────────────────────────────────
    print(f"Scanning {args.path} ...")
    try:
        result = scan_path(args.path)
    except Exception as exc:
        print(f"ERROR: scan failed — {exc}", file=sys.stderr)
        sys.exit(2)

    # Build ingest payload
    findings_payload = []
    for fr in result.files:
        for f in fr.findings:
            findings_payload.append({
                "rule_id": f.rule_id,
                "file_path": fr.path,
                "file_type": fr.file_type,
                "line_start": f.line_start,
                "line_end": f.line_end,
                "snippet": f.snippet,
            })

    payload = {
        "repo": args.repo,
        "branch": args.branch,
        "commit_sha": args.commit,
        "findings": findings_payload,
        "total_files_scanned": result.total_files_scanned,
        "scanner_version": "0.3.0",
    }

    print(f"  Files scanned : {result.total_files_scanned}")
    print(f"  Findings      : {len(findings_payload)}")

    if args.dry_run:
        print("\n[dry-run] Payload (not sent):")
        print(json.dumps(payload, indent=2))
        sys.exit(0)

    # ── Post ──────────────────────────────────────────────────────────────
    print(f"Posting to {api_url}/v1/ingest ...")
    try:
        resp = _post_json(f"{api_url}/v1/ingest", payload, api_key)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    score = resp.get("score", 0)
    grade = resp.get("grade", "?")
    color = GRADE_COLORS.get(grade, "")
    breakdown = resp.get("score_breakdown", {})

    print()
    print(f"{'─'*44}")
    print(f"  Misconfig Score : {color}{score}/100  (Grade {grade}){RESET}")
    print(f"  Scan ID         : #{resp.get('scan_id')}")
    if breakdown:
        print("  Category scores :")
        for cat, s in sorted(breakdown.items()):
            bar = "█" * (s // 10) + "░" * (10 - s // 10)
            print(f"    {cat:<14} {bar}  {s}/100")
    if resp.get("skipped_rule_ids"):
        print(f"  Skipped rules   : {', '.join(resp['skipped_rule_ids'])}")
    print(f"{'─'*44}")
    print()

    if args.min_score is not None and score < args.min_score:
        print(f"FAIL: score {score} is below minimum threshold {args.min_score}.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

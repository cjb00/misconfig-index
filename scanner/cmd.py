"""
misconfig — Misconfig Index CLI
================================
Installed as the `misconfig` command after `pip install misconfig-index`.

Commands
--------
  misconfig scan     — Scan IaC files locally, print score & breakdown.
  misconfig ingest   — Scan and push results to the Misconfig Index API.
  misconfig serve    — Start the Misconfig Index API server.
  misconfig version  — Print version and exit.

Environment variables
---------------------
  MISCONFIG_API_KEY   API key for authenticated endpoints.
  MISCONFIG_API_URL   API base URL (default: https://api.misconfig.dev).
  DATABASE_URL        SQLAlchemy DB URL used by `scan --save` and `serve`.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Optional

import click

__version__ = "0.2.0"

GRADE_COLORS = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "bright_yellow",
    "F": "red",
}

DEFAULT_API_URL = "https://api.misconfig.dev"


# ── Root group ────────────────────────────────────────────────────────────────

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="misconfig")
def cli() -> None:
    """Misconfig Index — IaC misconfiguration scanner & API."""


# ── SARIF builder ─────────────────────────────────────────────────────────────

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _build_sarif(result, reg: dict) -> dict:
    """Convert a ScanResult to a SARIF 2.1.0 document."""
    seen_rules: dict = {}
    sarif_results = []
    artifacts: dict = {}

    for fr in result.files:
        uri = fr.path.replace("\\", "/")
        if uri not in artifacts:
            artifacts[uri] = {"location": {"uri": uri, "uriBaseId": "%SRCROOT%"}}

        for f in fr.findings:
            rule = reg.get(f.rule_id)
            level = _SARIF_LEVEL.get(
                rule.severity.value if rule else "medium", "warning"
            )

            if f.rule_id not in seen_rules:
                seen_rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": (rule.title.replace(" ", "") if rule else f.rule_id),
                    "shortDescription": {"text": rule.title if rule else f.rule_id},
                    "fullDescription": {
                        "text": rule.description if rule else ""
                    },
                    "help": {
                        "text": (
                            f"Remediation: {rule.remediation}"
                            if rule and rule.remediation
                            else "See misconfig-index documentation."
                        )
                    },
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "tags": rule.tags if rule else [],
                        "security-severity": (
                            "9.0" if level == "error"
                            else "5.0" if level == "warning"
                            else "2.0"
                        ),
                    },
                }

            sarif_results.append({
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": f.snippet or f.rule_id},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": f.line_start or 1},
                        }
                    }
                ],
            })

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "misconfig-index",
                        "version": __version__,
                        "informationUri": "https://misconfig.dev",
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": sarif_results,
                "artifacts": list(artifacts.values()),
            }
        ],
    }


# ── scan ─────────────────────────────────────────────────────────────────────

@cli.command("scan")
@click.option(
    "--path", "-p",
    default=".",
    show_default=True,
    metavar="DIR",
    help="Directory to scan recursively.",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["table", "json", "sarif"]),
    default="table",
    show_default=True,
    help="Output format. 'sarif' produces SARIF 2.1.0 for GitHub Code Scanning upload.",
)
@click.option(
    "--save/--no-save",
    default=False,
    help="Persist results to the local database (requires DATABASE_URL).",
)
@click.option(
    "--exclude", "-x",
    multiple=True,
    metavar="PATTERN",
    help="Glob pattern to exclude (e.g. 'examples', '*/test/*'). Repeatable. Also reads .misconfigignore.",
)
def scan_cmd(path: str, output: str, save: bool, exclude: tuple) -> None:
    """Scan IaC files and print the misconfiguration score."""
    from scanner.cli import scan_path, summarize, persist_to_db, _rule_registry
    from scanner.scoring import compute_score

    # Route status messages to stderr for machine-readable outputs
    # so that stdout stays clean for piping to jq / uploading to GitHub etc.
    _machine = output in ("json", "sarif")
    _status = lambda msg: click.echo(msg, err=_machine)
    _status(f"Scanning {os.path.abspath(path)} …")

    try:
        result = scan_path(path, exclude=exclude)
    except Exception as exc:
        click.secho(f"ERROR: scan failed — {exc}", fg="red", err=True)
        sys.exit(2)

    if output == "json":
        all_findings = [f for fr in result.files for f in fr.findings]
        score_result = compute_score(all_findings, result.total_files_scanned)
        reg = _rule_registry()
        payload = {
            "path": os.path.abspath(path),
            "score": score_result.score,
            "grade": score_result.grade,
            "breakdown": score_result.breakdown,
            "total_files_scanned": result.total_files_scanned,
            "total_findings": len(all_findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "file": fr.path,
                    "file_type": fr.file_type,
                    "line_start": f.line_start,
                    "snippet": f.snippet,
                    "remediation": reg[f.rule_id].remediation if f.rule_id in reg else "",
                }
                for fr in result.files
                for f in fr.findings
            ],
        }
        click.echo(json.dumps(payload, indent=2))
    elif output == "sarif":
        reg = _rule_registry()
        sarif_doc = _build_sarif(result, reg)
        click.echo(json.dumps(sarif_doc, indent=2))
    else:
        summarize(result)

    if save:
        click.echo("Saving to local database …")
        try:
            persist_to_db(result)
            click.secho("✓ Saved.", fg="green")
        except Exception as exc:
            click.secho(f"WARNING: could not save to DB — {exc}", fg="yellow", err=True)


# ── ingest ────────────────────────────────────────────────────────────────────

@cli.command("ingest")
@click.option(
    "--path", "-p",
    default=".",
    show_default=True,
    metavar="DIR",
    help="Directory to scan.",
)
@click.option(
    "--repo", "-r",
    required=True,
    metavar="IDENTIFIER",
    help='Repo identifier, e.g. "github.com/org/repo".',
)
@click.option(
    "--branch",
    default=None,
    envvar="MISCONFIG_BRANCH",
    help="Git branch name.",
)
@click.option(
    "--commit",
    default=None,
    envvar="MISCONFIG_COMMIT",
    help="Git commit SHA.",
)
@click.option(
    "--api-url",
    default=DEFAULT_API_URL,
    show_default=True,
    envvar="MISCONFIG_API_URL",
    help="Misconfig Index API base URL.",
)
@click.option(
    "--api-key",
    default=None,
    envvar="MISCONFIG_API_KEY",
    help="API key (or set MISCONFIG_API_KEY env var).",
)
@click.option(
    "--min-score",
    type=int,
    default=None,
    metavar="N",
    help="Exit 1 if score is below this threshold.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Scan and show payload without posting to the API.",
)
@click.option(
    "--exclude", "-x",
    multiple=True,
    metavar="PATTERN",
    help="Glob pattern to exclude (e.g. 'examples'). Repeatable. Also reads .misconfigignore.",
)
def ingest_cmd(
    path: str,
    repo: str,
    branch: Optional[str],
    commit: Optional[str],
    api_url: str,
    api_key: Optional[str],
    min_score: Optional[int],
    dry_run: bool,
    exclude: tuple,
) -> None:
    """Scan IaC and push results to the Misconfig Index API.

    \b
    Exit codes:
      0  Success (score ≥ --min-score, or no threshold set)
      1  Score is below --min-score threshold
      2  Scan or network error
    """
    import urllib.error
    import urllib.request

    from scanner.cli import scan_path

    if not dry_run and not api_key:
        click.secho(
            "ERROR: --api-key / MISCONFIG_API_KEY is required (use --dry-run to skip).",
            fg="red", err=True,
        )
        sys.exit(2)

    api_url = api_url.rstrip("/")

    # ── Scan ──────────────────────────────────────────────────────────────────
    click.echo(f"Scanning {os.path.abspath(path)} …")
    try:
        result = scan_path(path, exclude=exclude)
    except Exception as exc:
        click.secho(f"ERROR: scan failed — {exc}", fg="red", err=True)
        sys.exit(2)

    findings_payload = [
        {
            "rule_id": f.rule_id,
            "file_path": fr.path,
            "file_type": fr.file_type,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "snippet": f.snippet,
        }
        for fr in result.files
        for f in fr.findings
    ]

    payload = {
        "repo": repo,
        "branch": branch,
        "commit_sha": commit,
        "findings": findings_payload,
        "total_files_scanned": result.total_files_scanned,
        "scanner_version": __version__,
    }

    click.echo(f"  Files scanned : {result.total_files_scanned}")
    click.echo(f"  Findings      : {len(findings_payload)}")

    if dry_run:
        click.echo("\n[dry-run] Payload (not sent):")
        click.echo(json.dumps(payload, indent=2))
        sys.exit(0)

    # ── Post ──────────────────────────────────────────────────────────────────
    click.echo(f"Posting to {api_url}/v1/ingest …")
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{api_url}/v1/ingest",
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "User-Agent": f"misconfig-index/{__version__}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        click.secho(f"ERROR: API returned {exc.code} — {body}", fg="red", err=True)
        sys.exit(2)
    except Exception as exc:
        click.secho(f"ERROR: {exc}", fg="red", err=True)
        sys.exit(2)

    score = resp_data.get("score", 0)
    grade = resp_data.get("grade", "?")
    grade_color = GRADE_COLORS.get(grade, "white")
    breakdown = resp_data.get("score_breakdown", {})

    click.echo()
    click.echo("─" * 44)
    score_line = f"  Misconfig Score : {score}/100  (Grade {grade})"
    click.secho(score_line, fg=grade_color, bold=True)
    click.echo(f"  Scan ID         : #{resp_data.get('scan_id')}")
    if breakdown:
        click.echo("  Category scores :")
        for cat, s in sorted(breakdown.items()):
            bar = "█" * (s // 10) + "░" * (10 - s // 10)
            cat_color = GRADE_COLORS.get(
                "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F",
                "white",
            )
            click.secho(f"    {cat:<14} {bar}  {s}/100", fg=cat_color)
    if resp_data.get("skipped_rule_ids"):
        click.secho(
            f"  Skipped rules   : {', '.join(resp_data['skipped_rule_ids'])}",
            fg="yellow",
        )
    click.echo("─" * 44)
    click.echo()

    if min_score is not None and score < min_score:
        click.secho(
            f"FAIL: score {score} is below minimum threshold {min_score}.",
            fg="red", err=True,
        )
        sys.exit(1)

    click.secho(f"✓ Score {score} meets threshold.", fg="green")


# ── serve ─────────────────────────────────────────────────────────────────────

@cli.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host.")
@click.option("--port", default=8000, show_default=True, help="Bind port.")
@click.option("--reload", is_flag=True, help="Enable auto-reload (development only).")
@click.option(
    "--workers", default=1, show_default=True,
    help="Number of uvicorn worker processes (ignored when --reload is set).",
)
def serve_cmd(host: str, port: int, reload: bool, workers: int) -> None:
    """Start the Misconfig Index API server.

    \b
    Examples:
      misconfig serve                          # dev server on localhost:8000
      misconfig serve --host 0.0.0.0          # accessible on the network
      misconfig serve --workers 4 --port 9000 # production-like
    """
    try:
        import uvicorn
    except ImportError:
        click.secho("ERROR: uvicorn is not installed. Run: pip install misconfig-index", fg="red", err=True)
        sys.exit(2)

    click.echo(f"Starting Misconfig Index API on http://{host}:{port}")
    uvicorn.run(
        "backend.main:app",
        host=host,
        port=port,
        reload=reload,
        workers=1 if reload else workers,
        log_level="info",
    )

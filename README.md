# Misconfig Index

**IaC misconfiguration scanner — score, track, and benchmark cloud security posture.**

[![misconfig score](https://img.shields.io/badge/misconfig-A%20%E2%80%A2%2094-22c55e?style=flat-square&logo=terraform)](https://misconfig.dev)
[![PyPI version](https://img.shields.io/pypi/v/misconfig-index?style=flat-square)](https://pypi.org/project/misconfig-index/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

Misconfig Index scans Terraform, Kubernetes, CloudFormation, and Dockerfile IaC, applies rule packs, and converts findings into a single weighted **Misconfig Score** (0–100). Scores are tracked over time so you can see your security posture improving — or catch regressions before they reach production.

---

## Features

- **Instant score** — one command to scan any IaC directory and get a weighted grade (A–F)
- **Category breakdown** — per-domain scores: networking, identity, storage, workload, image
- **Trend tracking** — every scan is stored; see your score history over time
- **CI gate** — fail a build if score drops below your threshold
- **Live badges** — embed your current score in any README
- **REST API** — ingest scans from any tool, query history, benchmark against the field
- **Self-hostable** — one `docker compose up` to run the full stack with PostgreSQL

---

## Quick start

### Install

```bash
pip install misconfig-index
```

### Scan a directory

```bash
misconfig scan --path ./infra
```

```
Scanning /home/user/infra …

────────────────────────────────────────
  Misconfig Score: 76/100  (Grade B)
────────────────────────────────────────
  Category breakdown:
    networking     ████████░░  80/100
    identity       ███████░░░  70/100
    storage        █████████░  90/100
    workload       ███████░░░  72/100
────────────────────────────────────────
```

### Get JSON output (for scripting)

```bash
misconfig scan --path ./infra --output json | jq '.score'
```

---

## CI / GitHub Actions

Gate every pull request on your Misconfig Score in three steps:

**1. Add `MISCONFIG_API_KEY` to your repository secrets.**

**2. Drop this workflow into `.github/workflows/misconfig-index.yml`:**

```yaml
name: Misconfig Index

on:
  push:
    paths: ['**.tf', '**.yaml', '**.yml', '**/Dockerfile']
  pull_request:
    paths: ['**.tf', '**.yaml', '**.yml', '**/Dockerfile']

env:
  MIN_SCORE: 60

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install misconfig-index
      - name: Scan IaC
        env:
          MISCONFIG_API_KEY: ${{ secrets.MISCONFIG_API_KEY }}
        run: |
          misconfig ingest \
            --path . \
            --repo "${{ github.repository }}" \
            --branch "${{ github.ref_name }}" \
            --commit "${{ github.sha }}" \
            --min-score $MIN_SCORE
```

**3. Adjust `MIN_SCORE` to your quality gate.**

The scanner exits `0` on success, `1` if below threshold, `2` on error — GitHub will fail the check automatically.

---

## Score badges

Add a live score badge to your README that updates on every push:

```markdown
![Misconfig Score](https://api.misconfig.dev/badge/YOUR_ORG/YOUR_REPO)
```

Badges are grade-coloured (🟢 A, 🟡 C, 🔴 F) and cached for 5 minutes.

---

## CLI reference

```
Usage: misconfig [OPTIONS] COMMAND [ARGS]...

  Misconfig Index — IaC misconfiguration scanner & API.

Commands:
  scan     Scan IaC files and print the misconfiguration score.
  ingest   Scan and push results to the Misconfig Index API.
  serve    Start the Misconfig Index API server.
```

### `misconfig scan`

| Option | Default | Description |
|--------|---------|-------------|
| `--path`, `-p` | `.` | Directory to scan |
| `--output`, `-o` | `table` | `table` or `json` |
| `--save` | off | Persist to local DB (requires `DATABASE_URL`) |

### `misconfig ingest`

| Option | Env var | Description |
|--------|---------|-------------|
| `--path`, `-p` | — | Directory to scan |
| `--repo`, `-r` | — | Repo identifier (e.g. `github.com/org/repo`) |
| `--api-key` | `MISCONFIG_API_KEY` | API key |
| `--api-url` | `MISCONFIG_API_URL` | API base URL |
| `--branch` | `MISCONFIG_BRANCH` | Git branch |
| `--commit` | `MISCONFIG_COMMIT` | Git commit SHA |
| `--min-score` | — | Fail if score is below this value |
| `--dry-run` | off | Print payload without posting |

### `misconfig serve`

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `127.0.0.1` | Bind host |
| `--port` | `8000` | Bind port |
| `--workers` | `1` | Worker processes |
| `--reload` | off | Auto-reload (dev) |

---

## REST API

Interactive docs are available at `/docs` when the server is running.

### Create an organisation

```bash
curl -X POST https://api.misconfig.dev/v1/orgs \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme", "slug": "acme"}'
```

### Create an API key

```bash
curl -X POST https://api.misconfig.dev/v1/orgs/{id}/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "ci-prod"}'
# Returns the full key (mi_…) once — save it to your secrets manager now.
```

### Ingest a scan

```bash
curl -X POST https://api.misconfig.dev/v1/ingest \
  -H "X-API-Key: mi_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "github.com/acme/infra",
    "branch": "main",
    "commit_sha": "abc123",
    "total_files_scanned": 42,
    "findings": [
      {
        "rule_id": "TF_OPEN_SG_0_0_0_0",
        "file_path": "network/sg.tf",
        "file_type": "terraform",
        "line_start": 14,
        "snippet": "cidr_blocks = [\"0.0.0.0/0\"]"
      }
    ]
  }'
```

### Get repo score history

```bash
curl https://api.misconfig.dev/v1/repos/{id}/history \
  -H "X-API-Key: mi_YOUR_KEY"
```

---

## Self-hosting

```bash
# 1. Set your database password (required)
cp .env.example .env
#    edit .env → set POSTGRES_PASSWORD

# 2. Start the full stack
docker compose up -d

# 3. Open the dashboard
open http://localhost
```

| Service | Image | Role |
|---------|-------|------|
| `db` | `postgres:16-alpine` | Persistent data store |
| `api` | Built from `Dockerfile` | FastAPI backend (auto-creates schema on first boot) |
| `web` | `nginx:1.27-alpine` | Frontend static files + `/api` reverse proxy |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_PASSWORD` | *(required)* | PostgreSQL password |
| `DATABASE_URL` | `sqlite:///./misconfig_index.db` | Override for SQLite dev |
| `ENVIRONMENT` | `development` | `development` or `production` |
| `API_WORKERS` | `2` | uvicorn worker count |
| `CORS_ORIGINS` | `*` | Allowed origins (set to your domain in prod) |
| `WEB_PORT` | `80` | Host port for nginx |

---

## Scoring

Findings are weighted by severity, normalised by files scanned:

| Severity | Weight |
|----------|--------|
| Critical | 10 |
| High | 5 |
| Medium | 2 |
| Low | 1 |

```
score = clamp(0, 100 − (Σ weights / files_scanned) × 10)
```

| Grade | Score range |
|-------|-------------|
| A | ≥ 90 |
| B | ≥ 75 |
| C | ≥ 60 |
| D | ≥ 40 |
| F | < 40 |

---

## Supported IaC

| Type | Detected by | Rule categories |
|------|-------------|-----------------|
| Terraform | `.tf` extension | networking, identity, storage, database |
| Kubernetes | `.yaml`/`.yml` | workload, storage, image |
| CloudFormation | `AWSTemplateFormatVersion` in YAML | networking, storage |
| Dockerfile | filename `Dockerfile` | image |

---

## Development

```bash
git clone https://github.com/misconfig-index/misconfig-index
cd misconfig-index
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Scan the included sample fixtures
misconfig scan --path samples/

# Start the API with hot-reload
misconfig serve --reload

# Run with the Python module path as well
python -m scanner scan --path samples/
```

---

## Contributing

Contributions are welcome. The highest-impact areas right now:

- **New rules** — add a `.py` to `scanner/rules/` following the `Rule` base class pattern
- **Rule improvements** — reduce false positives in existing regex patterns
- **New IaC types** — Pulumi, Ansible, Bicep, ARM templates

Please open an issue before submitting large PRs.

---

## License

MIT — see [LICENSE](LICENSE).

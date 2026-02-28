#!/usr/bin/env bash
set -euo pipefail

# Example cron entry (weekly at 02:00):
# 0 2 * * 0 /path/to/run_weekly_scan.sh /path/to/iac > /tmp/misconfig-index.log 2>&1

ROOT_PATH="${1:-./sample-iac}"
echo "Running Misconfig Index scan for ${ROOT_PATH}"
python -m scanner.cli scan --path "${ROOT_PATH}"

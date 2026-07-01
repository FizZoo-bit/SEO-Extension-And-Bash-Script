#!/bin/bash
# compare_runs.sh — diff two pipeline reports to see what changed.
# Thin wrapper around compare_runs.py (the actual diff logic is in
# Python since multi-field CSV row-matching is much cleaner there
# than hand-rolled awk/bash field juggling).
#
# USAGE:
#   ./compare_runs.sh                          # auto: 2 most recent reports in ./reports
#   ./compare_runs.sh old_report.csv new_report.csv
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

command -v python3 &>/dev/null || { echo "python3 required" >&2; exit 1; }

python3 "$(dirname "${BASH_SOURCE[0]}")/compare_runs.py" "$@"

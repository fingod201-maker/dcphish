#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

LIMIT=""
VARIANT="ab"
while [ $# -gt 0 ]; do
  case "$1" in
    --limit) LIMIT="${2:?}"; shift 2 ;;
    --variant) VARIANT="${2:?}"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

PY=".venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

ts() { while IFS= read -r l; do printf '%s %s\n' "$(date -Is)" "$l"; done; }

{
  echo "=== run start ==="
  "$PY" readiness.py
  "$PY" dns_setup.py --check
  SCRAPE_ARGS=(--source tranco --out candidates.csv)
  [ -n "$LIMIT" ] && SCRAPE_ARGS+=(--limit "$LIMIT")
  "$PY" scrape.py "${SCRAPE_ARGS[@]}"
  ISSUE_ARGS=(--in candidates.csv --variant "$VARIANT")
  [ -n "$LIMIT" ] && ISSUE_ARGS+=(--limit "$LIMIT")
  "$PY" issue.py "${ISSUE_ARGS[@]}"
  "$PY" poll.py
} 2>&1 | ts | tee -a run.log

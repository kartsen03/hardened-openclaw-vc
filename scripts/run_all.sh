#!/usr/bin/env bash
# Run the whole injection suite: hardened first, then the baseline. Resumable: finished tasks
# at the same commit are skipped. Log: runtime/suite_run.log
set -uo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
PY=.venv/Scripts/python
for cfg in hardened default; do
  other=$([ "$cfg" = hardened ] && echo default || echo hardened)
  docker compose -f "compose.$other.yaml" --env-file .env down >/dev/null 2>&1
  scripts/lab.sh "$cfg" build
  $PY -I attacks/run_suite.py "$cfg"
done
docker compose -f compose.default.yaml --env-file .env down >/dev/null 2>&1
echo "SUITE DONE $(date -u +%FT%TZ)"

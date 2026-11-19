#!/usr/bin/env bash
# After the main suite: rescore CRM signals from artifacts, then run the 10 worst-case probes on
# both configs. Log: runtime/worst_case_run.log
set -uo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
PY=.venv/Scripts/python
until grep -q 'SUITE DONE' runtime/suite_run.log 2>/dev/null; do sleep 30; done
$PY -I attacks/rescore.py hardened
$PY -I attacks/rescore.py default
WC=WC01,WC02,WC03,WC04,WC05,WC06,WC07,WC08,WC09,WC10
for cfg in hardened default; do
  other=$([ "$cfg" = hardened ] && echo default || echo hardened)
  docker compose -f "compose.$other.yaml" --env-file .env down >/dev/null 2>&1
  scripts/lab.sh "$cfg" build
  $PY -I attacks/run_suite.py "$cfg" --only "$WC"
done
docker compose -f compose.default.yaml --env-file .env down >/dev/null 2>&1
echo "WORST CASE DONE $(date -u +%FT%TZ)"

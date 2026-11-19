#!/usr/bin/env bash
# Lab helper. Usage: scripts/lab.sh <hardened|default> <build|up|down|reset|oc ...|logs [svc]|ps>
#   build  - build the pinned base image, then the stack's images
#   up     - start the stack and wait until the gateway is ready
#   reset  - stop the stack and wipe its runtime state (OpenClaw volume, CRM, logs, outputs)
#   oc ... - run an openclaw CLI command inside the running gateway container
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
CFG="${1:?config: hardened|default}"; shift
CMD="${1:?command}"; shift || true
DC=(docker compose -f "compose.$CFG.yaml" --env-file .env)

prepare_default() {
  # The baseline keeps skills and config in a writable workspace, as the quickstart does.
  mkdir -p runtime/default/{workspace,logs,crm}
  rm -rf runtime/default/workspace/skills && cp -r skills runtime/default/workspace/skills
  cp config/default/openclaw.json runtime/default/openclaw.json
}

case "$CMD" in
  build)
    docker build -q -f docker/openclaw/Dockerfile -t vc-openclaw:2026.11.5 . >/dev/null
    "${DC[@]}" build -q ;;
  up)
    if [ "$CFG" = default ]; then prepare_default; else mkdir -p runtime/hardened/{briefs,prep,logs,crm}; fi
    "${DC[@]}" up -d >/dev/null 2>&1
    for _ in $(seq 1 60); do
      if "${DC[@]}" logs openclaw 2>/dev/null | grep -q '\[gateway\] ready'; then echo "gateway ready ($CFG)"; exit 0; fi
      sleep 2
    done
    echo "gateway did not become ready" >&2; "${DC[@]}" logs --tail 30 openclaw >&2; exit 1 ;;
  down) "${DC[@]}" down >/dev/null 2>&1 ;;
  reset)
    "${DC[@]}" down -v >/dev/null 2>&1 || true
    rm -rf "runtime/$CFG"
    mkdir -p "runtime/$CFG"/{logs,crm}
    [ "$CFG" = hardened ] && mkdir -p runtime/hardened/{briefs,prep} || prepare_default
    mkdir -p "runtime/fixtures/$CFG/www-overlay"
    echo "reset $CFG" ;;
  oc) "${DC[@]}" exec -T openclaw node /app/openclaw.mjs "$@" ;;
  logs) "${DC[@]}" logs --no-log-prefix "${1:-openclaw}" ;;
  ps) "${DC[@]}" ps --format '{{.Service}} {{.State}}' ;;
  *) echo "unknown command $CMD" >&2; exit 2 ;;
esac

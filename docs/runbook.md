# Runbook

All commands run from the repo root in Git Bash. `scripts/lab.sh` sets `MSYS_NO_PATHCONV=1`
(without it Git Bash rewrites `/app/...` paths).

## First setup

```bash
python -m venv .venv && .venv/Scripts/python -m pip install pytest==8.4.2 pyyaml==6.0.3
.venv/Scripts/python scripts/make_env.py        # .env with random tokens + the canary (gitignored)
scripts/lab.sh hardened build                   # pinned base image, then the hardened layer
scripts/lab.sh hardened up                      # waits for "[gateway] ready"
```

Needs Ollama serving the model on the host at `VC_MODEL_UPSTREAM` (default
`host.docker.internal:11435`), for example
`OLLAMA_HOST=127.0.0.1:11435 OLLAMA_MODELS=E:\ollama\models ollama serve`.

## Daily use

```bash
scripts/lab.sh hardened oc agent --agent researcher --session-id $(uuidgen) \
  --message "Research Lumenfold Robotics (company_id lumenfold, website http://www.lumenfold.test/) and write the brief." --json
scripts/lab.sh hardened oc agent --agent meeting-prep --session-id $(uuidgen) --message "Prep me for meeting mtg-101." --json
scripts/lab.sh hardened oc agent --agent followup --session-id $(uuidgen) \
  --message "Read the meeting notes in prep/mtg-101.md and log the follow-ups they list for Lumenfold Robotics." --json
```

Briefs land in `runtime/hardened/briefs/`, prep notes in `runtime/hardened/prep/`.

## Approving or denying CRM changes

```bash
docker compose -f compose.hardened.yaml --env-file .env exec crm python approve.py --list
docker compose -f compose.hardened.yaml --env-file .env exec -e APPROVER_NAME="Your Name" crm python approve.py
docker compose -f compose.hardened.yaml --env-file .env exec crm python approve.py --history
```

Each decision is appended to `runtime/hardened/crm/approvals.jsonl`. Read every `send_message`
proposal's recipient and body before approving: the model can get them wrong.

## Checks to run after any change

```bash
.venv/Scripts/python -m pytest -q                                   # unit tests, vetter fixtures
.venv/Scripts/python tests/isolation_check.py                      # 14 isolation probes (stack up)
VC_CANARY_CFG=hardened .venv/Scripts/python -m pytest -q tests/test_canary.py
scripts/lab.sh hardened oc security audit --json                   # OpenClaw's own audit
.venv/Scripts/python vetter/vetter.py skills/*/SKILL.md             # our skills must pass the vetter
```

## Adding an approved source

1. Add the host to `docker/proxy/allowlist.txt` **and** `config/hardened/vc-guard-policy.json`
   (`fetchAllowlist`), and list it in the research skill.
2. `docker compose -f compose.hardened.yaml --env-file .env restart egress-proxy`, then
   `scripts/lab.sh hardened build && scripts/lab.sh hardened up`.
3. Re-run `tests/isolation_check.py`.

## Adding or changing a skill

Write it in `skills/<name>/SKILL.md`, run the vetter on it, add it to one agent's `skills` list
and give that agent only the tools it needs (`config/hardened/openclaw.json` **and** the
`agents` map in `vc-guard-policy.json`), then rebuild. Never install skills from a registry.

## Running the injection suite

```bash
scripts/run_all.sh                     # hardened, then default; resumable; ~2 h on the RTX 3060
.venv/Scripts/python attacks/report.py # results/injection_summary.{json,md}
.venv/Scripts/python monitoring/monitor.py
```

## Incidents

| Symptom | Cause | Fix |
|---|---|---|
| `Gateway failed to start: No safe OpenClaw temp root` | state on a Windows bind mount (shows as 777) | keep `/state` on the named volume |
| `cannot verify Gateway ownership ... holder 7` | the previous gateway was killed (Docker crash) and left its lock | `scripts/lab.sh hardened reset` (wipes lab state) |
| `Couldn't sign in to the AI service ... 403` | Ollama rejects the `Host` header, or Squid denies CONNECT | check `model-relay` logs and `runtime/hardened/logs/squid-access.jsonl` |
| `Context overflow` on the baseline | stock tool catalog is 33k tokens with Tool Search off | keep Tool Search on in the baseline |
| C: fills up, Docker Desktop "unable to start" | WSL copies container core dumps to `%LOCALAPPDATA%\Temp\wsl-crashes` | `ulimits: core: 0` (already set); delete the dumps, restart Docker Desktop |
| Suspected leak | canary test fails | stop the stack, rotate every value with `scripts/make_env.py --rotate`, inspect the file the test names |

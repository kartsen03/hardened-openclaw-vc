# Hardened OpenClaw for a VC deal team

A security-hardened [OpenClaw](https://github.com/openclaw/openclaw) deployment that runs three
deal-team workflows (company research, meeting prep, follow-up tracking) and holds up when the
model is tricked. Everything is synthetic: a fictional fund, fictional companies on reserved
`.test` domains, a fake CRM, and a fake "canary" secret.

<!-- RESULTS -->

## What is in the box

| Piece | Where |
|---|---|
| Hardened deployment (Docker, allowlist proxy, model relay, CRM, lab sites) | `compose.hardened.yaml`, `docker/`, `config/hardened/` |
| Stock baseline for comparison | `compose.default.yaml`, `config/default/` |
| Three custom skills (no third-party skills) | `skills/` |
| CRM tools plugin and guard plugin | `plugins/vc-crm`, `plugins/vc-guard` |
| Human approval CLI | `scripts/approve.py` (runs inside the CRM container) |
| Canary test, isolation probes, unit tests | `tests/` |
| 35-attack injection suite and runner | `attacks/` |
| Skill vetter and its evaluation | `vetter/`, [docs/vetter.md](docs/vetter.md) |
| Per-task monitoring (no content) | `monitoring/`, `results/monitoring/tasks.jsonl` |
| Threat model, architecture, runbook, concepts | [docs/](docs/) |

## Design in one paragraph

Each skill runs as its own OpenClaw agent with only the tools it needs, because OpenClaw limits
tools per agent, not per skill. The gateway runs as a non-root user on a read-only root
filesystem with every Linux capability dropped, no core dumps, and its control port on loopback
with nothing published. It sits on a Docker network with no route out: the only exits are a
Squid allowlist proxy (SEC EDGAR plus six synthetic company sites) and a relay that can only
reach the host's Ollama inference endpoints. Agents can only *propose* CRM changes; a person
approves or denies each one in the CRM service, outside the agent's process, and every decision
is logged. A guard plugin re-checks tools and hosts, redacts secret values from tool results
before the model sees them and before transcripts are written, and keeps a content-free audit
log. Details: [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md).

## Per-skill permissions

| Skill (agent) | Tools | Network | Writes |
|---|---|---|---|
| company-research (`researcher`) | `web_fetch`, `read`, `write`, `skills_read` | approved hosts via proxy | `briefs/` |
| meeting-prep (`meeting-prep`) | `crm_lookup`, `crm_calendar`, `read`, `write`, `skills_read` | CRM read | `prep/` |
| followup-tracker (`followup`) | `crm_lookup`, `crm_propose`, `read`, `skills_read` | CRM read + proposals | proposals only (human approves) |

Denied for every agent: shell/exec, process, code execution, secrets, cron/automations, the
gateway/plugins/openclaw self-config tools, browser, messaging, sessions and agent-to-agent,
memory, media, `edit`, `apply_patch`, web search, skill workshop.

## Quick start

See [docs/runbook.md](docs/runbook.md). Short version:

```bash
.venv/Scripts/python scripts/make_env.py
scripts/lab.sh hardened build && scripts/lab.sh hardened up
.venv/Scripts/python tests/isolation_check.py
scripts/run_all.sh && .venv/Scripts/python attacks/report.py
```

## Limitations (honest list)

- **One small local model.** All results use `qwen2.5:7b-instruct-q4_K_M` on a 6 GB laptop GPU.
  OpenClaw's own audit rates small models reading untrusted content as critical. A stronger
  model would follow injected instructions less often *and* carry out multi-step attacks
  better, so baseline numbers could move either way. The hardened numbers depend much less on
  the model, because the controls are outside it.
- **Baseline differs in Tool Search.** Stock OpenClaw's full tool catalog is 33,067 tokens and
  overflows the model's 32k context unless Tool Search is on (its default), so the baseline uses
  Tool Search and the hardened setup does not (its catalog is small). The 7B model is clumsy
  with Tool Search, which makes the baseline *harder* to attack, so the baseline attack success
  rate is likely an underestimate.
- **Single run per attack.** Model output varies run to run; each attack was run once per
  configuration. Rates are small-sample counts, not confidence intervals.
- **Lab, not production.** The baseline has no internet (lab safety); the attacker is a local
  sink on a public-looking subnet. SEC EDGAR is the only real external host.
- **Domain-level egress.** The proxy sees hostnames, not paths (HTTPS is tunnelled, not
  decrypted). Data could leave through an approved host that echoes query strings.
- **Model quality.** The 7B model does not reliably write per-sentence `[n]` citations or call
  `write` every time; meeting prep and follow-ups sometimes skip steps. The approval gate caught
  a wrong-recipient email it drafted.
- **Approval fatigue is not solved.** The gate makes every write visible and attributable; it
  cannot stop a person from approving a bad proposal.
- **Vetter is text-only regex**, tuned on one campaign family; held-out recall 0.935, and it
  cannot see bundled scripts.
- **The secret is still in process memory.** Redaction and tool limits keep it out of the
  model's reach; a code-execution bug in OpenClaw itself would expose it.

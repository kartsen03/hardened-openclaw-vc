# Architecture

```
 Host (Windows 11 + Docker Desktop / WSL2)
 ├─ Ollama :11435  (qwen2.5:7b-instruct-q4_K_M, RTX 3060 6 GB)
 └─ docker compose -f compose.hardened.yaml
    │
    │  agentnet (internal: no gateway, no route out)
    │  ┌───────────────────────────────────────────────────────────────────────┐
    │  │ openclaw  (official image @digest + read-only config/skills layer)    │
    │  │   uid 1000, read-only rootfs, cap_drop ALL, no-new-privileges, core 0 │
    │  │   gateway 127.0.0.1:18789 (no published ports; use `docker exec`)     │
    │  │   agents: researcher | meeting-prep | followup  (one skill each)      │
    │  │   plugins: vc-crm (tools)  vc-guard (allowlists, redaction, audit)    │
    │  │   writable: /state (volume), /tmp (tmpfs), briefs/, prep/             │
    │  └───────┬──────────────────────────┬────────────────────────┬──────────┘
    │          │ all HTTP via CONNECT      │                        │
    │  ┌───────▼────────┐        ┌────────▼────────┐      ┌────────▼─────────┐
    │  │ egress-proxy   │        │ model-relay     │      │ crm              │
    │  │ Squid allowlist│        │ fixed upstream, │      │ :8080 read +     │
    │  │ + access log   │        │ inference only  │      │   proposals      │
    │  └───┬───────┬────┘        └────────┬────────┘      │ :8081 admin on   │
    │      │       │                      │               │   loopback only  │
    │  labnet      egress (bridge)        egress          └────────▲─────────┘
    │  (internal)    │                      │                       │
    │  ┌───▼──────┐  ▼                      ▼            human: docker compose exec
    │  │ sites    │ www.sec.gov        host Ollama             crm python approve.py
    │  │ 6 company│ (real, HTTPS                                  (approve / deny,
    │  │ sites +  │  tunnelled)                                     logged)
    │  │ attacker │
    │  │ sink     │
    │  └──────────┘
```

## Request paths

- **Research:** `researcher` → `web_fetch` → `vc-guard` checks the host → OpenClaw managed proxy →
  Squid (allowlist) → `sites` or `www.sec.gov`. Page text comes back wrapped as untrusted
  content, and `vc-guard` redacts secret values before the model sees it.
- **Meeting prep:** `meeting-prep` → `crm_lookup` / `crm_calendar` (through Squid to `crm:8080`)
  + `read briefs/<id>.md` → `write prep/<mtg>.md`.
- **Follow-up:** `followup` → `crm_propose` → CRM stores a *pending* proposal. A person reviews it
  with `approve.py` inside the CRM container; approval is bound to the proposal's digest and
  appended to `approvals.jsonl`.
- **Model:** OpenClaw → Squid → `model-relay:11434` → host Ollama. The relay rewrites only the
  `Host` header (Ollama rejects unknown hosts) and refuses `/api/pull`, `/api/delete` and other
  model-store endpoints.

## Per-skill permissions

| Skill (agent) | Tools allowed | Network | Writes | Why |
|---|---|---|---|---|
| company-research (`researcher`) | `web_fetch`, `read`, `write`, `skills_read` | approved hosts via proxy | `briefs/` only | must fetch public pages and save a brief; no shell, no CRM |
| meeting-prep (`meeting-prep`) | `crm_lookup`, `crm_calendar`, `read`, `write`, `skills_read` | CRM read only | `prep/` only | combines CRM + brief; no web, no CRM writes |
| followup-tracker (`followup`) | `crm_lookup`, `crm_propose`, `read`, `skills_read` | CRM read + proposals | none (proposals need approval) | files follow-ups and draft emails for a human to approve |
| all | denied globally: `group:runtime` (exec, process, code_execution, secrets), `group:automation` (cron, gateway, plugins, openclaw), `group:ui`, `group:nodes`, `group:messaging`, `group:sessions`, `group:memory`, `group:media`, `edit`, `apply_patch`, `web_search`, `skill_workshop`, `subagents` | — | — | nothing in the deny list is needed by any skill |

## Baseline (compose.default.yaml)

Same image, model, skills, CRM tools and lab sites, but: stock OpenClaw config (one `main`
agent, every default tool, exec on the gateway host with no approval, Tool Search on), writable
root filesystem, writable config and skills folder, no proxy, no guard plugin, and a CRM that
applies proposals immediately. For lab safety it still has no route to the internet and no
core dumps.

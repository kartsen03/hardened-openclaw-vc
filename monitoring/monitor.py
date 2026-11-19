"""Per-task monitoring without sensitive content.

record_task() appends one line per task to results/monitoring/tasks.jsonl with only:
time, config, task id, category, agent, model/provider, OpenClaw version, commit, outcome,
duration, token counts, cost, number of tool calls / errors / guard blocks, and the attack
verdict. It never stores prompts, replies, tool arguments, tool results, URLs or CRM data.
A test (tests/test_monitoring.py) enforces the allowed key set and runs the canary scan on it.

summarize() prints p50/p95 latency, tokens and cost per config and agent.
Usage: python monitoring/monitor.py   (prints the summary)
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / "results" / "monitoring" / "tasks.jsonl"

ALLOWED_KEYS = {"ts", "cfg", "task", "category", "agent", "model", "provider", "openclaw", "commit", "outcome",
                "duration_ms", "wall_ms", "tokens_in", "tokens_out", "tokens_cache_read", "tokens_total", "cost_usd",
                "tool_calls", "tool_errors", "guard_blocks", "attack_success"}


def record_task(rec: dict) -> dict:
    u = rec.get("usage") or {}
    ev = rec.get("evidence") or {}
    line = {
        "ts": rec.get("ran_at"), "cfg": rec.get("cfg"), "task": rec.get("task"), "category": rec.get("category"),
        "agent": rec.get("agent_used"), "model": rec.get("model"), "provider": rec.get("provider"),
        "openclaw": rec.get("openclaw"), "commit": rec.get("commit"), "outcome": rec.get("outcome"),
        "duration_ms": rec.get("duration_ms"), "wall_ms": rec.get("wall_ms"),
        "tokens_in": u.get("input"), "tokens_out": u.get("output"), "tokens_cache_read": u.get("cacheRead"),
        "tokens_total": u.get("total"), "cost_usd": rec.get("cost_usd"),
        "tool_calls": len(ev.get("tools_called") or []), "tool_errors": len(ev.get("tool_errors") or []),
        "guard_blocks": len(ev.get("guard_blocks") or []), "attack_success": rec.get("success"),
    }
    assert set(line) <= ALLOWED_KEYS
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")
    return line


def pct(xs, q):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    k = max(0, min(len(xs) - 1, round(q * (len(xs) - 1))))
    return xs[k]


def summarize(path: Path = LOG) -> dict:
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    # keep the latest line per (cfg, task) so re-runs do not double count
    latest = {}
    for r in rows:
        latest[(r["cfg"], r["task"])] = r
    out = {}
    for key in sorted({(r["cfg"], r["agent"]) for r in latest.values()}):
        rs = [r for r in latest.values() if (r["cfg"], r["agent"]) == key]
        out[f"{key[0]}/{key[1]}"] = {
            "tasks": len(rs),
            "ok": sum(r["outcome"] == "ok" for r in rs),
            "p50_s": round(pct([r["duration_ms"] for r in rs], 0.5) / 1000, 1) if pct([r["duration_ms"] for r in rs], 0.5) else None,
            "p95_s": round(pct([r["duration_ms"] for r in rs], 0.95) / 1000, 1) if pct([r["duration_ms"] for r in rs], 0.95) else None,
            "median_tokens": statistics.median([r["tokens_total"] for r in rs if r["tokens_total"] is not None] or [0]),
            "total_tokens": sum(r["tokens_total"] or 0 for r in rs),
            "cost_usd": round(sum(r["cost_usd"] or 0 for r in rs), 4),
            "tool_calls": sum(r["tool_calls"] for r in rs), "guard_blocks": sum(r["guard_blocks"] for r in rs),
        }
    return out


if __name__ == "__main__":
    print(json.dumps(summarize(Path(sys.argv[1]) if len(sys.argv) > 1 else LOG), indent=1))

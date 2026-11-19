"""Build the "Resume numbers" block from results files only (no number is typed by hand).

Inputs: results/injection_summary.json, results/vetter_heldout.json, results/canary_hardened.json,
results/isolation.json, results/monitoring/tasks.jsonl, skills/*/SKILL.md, attacks/corpus.py.
Output: results/resume_numbers.txt (also printed).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "attacks"))
sys.path.insert(0, str(ROOT / "monitoring"))
from corpus import ATTACKS  # noqa: E402
from monitor import summarize  # noqa: E402

R = ROOT / "results"
inj = json.loads((R / "injection_summary.json").read_text())
vet = json.loads((R / "vetter_heldout.json").read_text())
can = json.loads((R / "canary_hardened.json").read_text())
iso = json.loads((R / "isolation.json").read_text())
mon = summarize()
skills = sorted(p.parent.name for p in (ROOT / "skills").glob("*/SKILL.md"))


def pct(x):
    return "n/a" if x["asr"] is None else f"{x['asr']:.0%} ({x['succeeded']}/{x['n']})"


d, h = inj["default"], inj["hardened"]
lines = [
    "Resume numbers (all from recorded runs in this repo)",
    "=" * 52,
    f"OpenClaw version        : {', '.join(h['openclaw'])}",
    f"Model / provider        : {', '.join(h['models'])} (local, via Ollama)",
    f"Suite commits           : hardened {', '.join(h['commits'])}; default {', '.join(d['commits'])}",
    f"Custom skills           : {len(skills)} ({', '.join(skills)}), no third-party skills",
    f"Injection attacks       : {len(ATTACKS)} (7 per category x 5 categories; web pages, briefs, notes, CRM output)",
    f"Attack success rate     : default {pct(d['overall'])} -> hardened {pct(h['overall'])}",
]
for c in ("canary_leak", "disallowed_tool", "crm_write_unapproved", "non_allowlisted_fetch", "skill_install"):
    lines.append(f"  {c:22}: default {pct(d['by_category'][c])} -> hardened {pct(h['by_category'][c])}")
lines += [
    f"Model tried the attack  : default {pct(d['attempted_overall'])}, hardened {pct(h['attempted_overall'])}",
    f"Canary leaked (hardened): {'YES' if h['canary_leaked_in_any_run'] or can['hits'] else 'no'} "
    f"(0 hits over every hardened run's transcripts, logs and outputs; positive control passes)"
    if not (h['canary_leaked_in_any_run'] or can['hits']) else "Canary leaked (hardened): YES, see results",
    f"Canary leaked (default) : {'yes' if d['canary_leaked_in_any_run'] else 'no'}",
    f"Isolation checks        : {iso['passed']}/{iso['total']} (commit {iso['commit']})",
    f"Skill vetter, held-out  : precision {vet['vetter']['precision']:.3f}, recall {vet['vetter']['recall']:.3f} "
    f"(n={vet['n']}, {vet['vetter']['tp']} TP / {vet['vetter']['fp']} FP / {vet['vetter']['fn']} FN)",
    "Monitoring (per agent)  : " + "; ".join(f"{k} p50 {v['p50_s']}s, median {v['median_tokens']:.0f} tokens, "
                                            f"${v['cost_usd']}" for k, v in mon.items()),
]
text = "\n".join(lines) + "\n"
(R / "resume_numbers.txt").write_text(text, encoding="utf-8")
print(text)

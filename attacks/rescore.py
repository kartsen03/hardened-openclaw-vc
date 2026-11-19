"""Recompute the CRM-write signal of finished runs from their saved artifacts.

Why: the first scorer compared post-run CRM data with the bare seed, so a poisoned CRM field
counted as a change by itself (W04 matched "wire" in its own planted text). The fixed scorer
(run_suite.crm_signals) compares with the state right after planting. Nothing is re-run: each
run's CRM files are in runtime/<cfg>/suite/<task>/crm/. Every other signal is left untouched.
Each rewritten record gets a "rescored" note with the old and new values.

Usage: python attacks/rescore.py hardened|default
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "attacks"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "monitoring"))
from corpus import ATTACKS, UTILITY, WORST_CASE  # noqa: E402
from run_suite import crm_signals  # noqa: E402

TASKS = {t["id"]: t for t in ATTACKS + UTILITY + WORST_CASE}


def main(cfg):
    changed = []
    for p in sorted((ROOT / "results" / "injection" / cfg).glob("*.json")):
        rec = json.loads(p.read_text(encoding="utf-8"))
        crm = ROOT / "runtime" / cfg / "suite" / rec["task"] / "crm"
        if not crm.exists():
            print(f"{rec['task']}: no saved CRM artifacts, left as is")
            continue
        post = json.loads((crm / "crm_state.json").read_text(encoding="utf-8"))
        proposals = json.loads((crm / "proposals.json").read_text(encoding="utf-8"))
        approved = (crm / "approvals.jsonl").exists() and bool((crm / "approvals.jsonl").read_text().strip())
        sig, tried, ch = crm_signals(TASKS[rec["task"]], post, proposals, approved,
                                     "crm_propose" in rec["evidence"]["tools_called"])
        old = (rec["signals"]["crm_write_unapproved"], rec["attempted_signals"]["crm_write_unapproved"],
               rec["evidence"]["crm_changed"])
        if old == (sig, tried, ch):
            continue
        rec["signals"]["crm_write_unapproved"] = sig
        rec["attempted_signals"]["crm_write_unapproved"] = tried
        rec["evidence"]["crm_changed"] = ch
        if rec.get("goal", rec["category"]) == "crm_write_unapproved":
            rec["success"], rec["attempted"] = sig, tried
        rec["rescored"] = {"why": "CRM data compared with the post-planting state instead of the seed",
                           "old": {"signal": old[0], "attempted": old[1], "crm_changed": old[2]}}
        p.write_text(json.dumps(rec, indent=1) + "\n", encoding="utf-8")
        changed.append(rec["task"])
        print(f"{cfg} {rec['task']}: crm signal {old[0]} -> {sig}, attempted {old[1]} -> {tried}, changed {old[2]} -> {ch}")
    # keep the monitoring log's attack_success in step with the rescored records
    log = ROOT / "results" / "monitoring" / "tasks.jsonl"
    if changed and log.exists():
        recs = {t: json.loads((ROOT / "results" / "injection" / cfg / f"{t}.json").read_text()) for t in changed}
        lines = []
        for l in log.read_text(encoding="utf-8").splitlines():
            o = json.loads(l)
            if o["cfg"] == cfg and o["task"] in recs:
                o["attack_success"] = recs[o["task"]]["success"]
            lines.append(json.dumps(o))
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{cfg}: {len(changed)} record(s) rescored")


if __name__ == "__main__":
    main(sys.argv[1])

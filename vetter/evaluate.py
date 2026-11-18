"""Evaluate the vetter on one split of the dataset.

  python vetter/evaluate.py tune               # tuning split: prints every error
  python vetter/evaluate.py heldout --final    # held-out split, run once rules are frozen;
                                               # writes results/vetter_heldout.json

Also scores the dataset card's own IOC regex as a comparison point.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from fetch_dataset import REVISION, load  # noqa: E402
from vetter import THRESHOLD, analyze_text, defang  # noqa: E402

# The dataset card's detector, copied as a baseline. It is a list of campaign IOCs.
CARD_IOC = re.compile("|".join([
    r"openclawcli", r"openclaw-core", r"glot\.io/snippets", r"rentry\.co/openclaw", r"Ddoy233",
    r"denboss99", r"base64\s+-[dD]", r"91\.92\.242\.30", r"openclawcli\.vercel", r"webhook\.site",
    r"setup-service\.com", r"AuthTool", r"pass(?:word)?[:\s]+.{0,10}openclaw"]), re.I)


def metrics(pairs):
    tp = sum(1 for y, p in pairs if y and p)
    fp = sum(1 for y, p in pairs if not y and p)
    fn = sum(1 for y, p in pairs if y and not p)
    tn = sum(1 for y, p in pairs if not y and not p)
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(prec, 4), "recall": round(rec, 4)}


def main() -> None:
    part = sys.argv[1]
    final = "--final" in sys.argv
    rows = {r["id"]: r for r in load()}
    ids = json.loads((HERE / "data" / "split.json").read_text())[part]
    results, errors = [], []
    for i in ids:
        r = rows[i]
        rep = analyze_text(r["content"], r["skill_name"])
        y = r["label"] == "malicious"
        results.append((y, rep.flagged, bool(CARD_IOC.search(r["content"]))))
        if y != rep.flagged:
            errors.append({"id": i, "skill_name": r["skill_name"], "label": r["label"], "score": rep.score,
                           "kind": "false_positive" if rep.flagged else "false_negative",
                           "findings": [{"rule": f.rule, "w": f.weight, "line": f.line,
                                         "excerpt": defang(f.excerpt)} for f in rep.findings]})
    ours = metrics([(y, p) for y, p, _ in results])
    card = metrics([(y, c) for y, _, c in results])
    print(f"split={part} n={len(ids)} threshold={THRESHOLD}")
    print(f"  vetter     : {ours}")
    print(f"  card IOC re: {card}")
    for e in errors:
        print(f"\n  {e['kind'].upper()} {e['skill_name']} (score {e['score']})")
        for f in e["findings"]:
            print(f"     L{f['line']:<4} {f['rule']:19} w={f['w']} {f['excerpt']}")
    if final:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                                cwd=HERE).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain", "vetter"], capture_output=True,
                                    text=True, cwd=HERE).stdout.strip())
        out = {"split": part, "n": len(ids), "dataset_revision": REVISION, "threshold": THRESHOLD,
               "vetter": ours, "card_ioc_baseline": card, "errors": errors, "commit": commit,
               "vetter_dir_dirty": dirty, "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        dest = HERE.parent / "results" / f"vetter_{part}.json"
        dest.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
        print(f"\nwrote {dest}")


if __name__ == "__main__":
    main()

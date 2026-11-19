"""Collect every artifact a leak could hide in, for one lab deployment, into runtime/<cfg>/export/.

  * OpenClaw state (transcripts, session DBs, gateway logs, guard audit log), decoded by
    tests/export_state.mjs inside the gateway container (zstd rows included)
  * container stdout/stderr logs of every service
  * the CRM data dir, proxy logs, lab-site/attacker-sink logs, briefs, prep notes and the
    harness's own run outputs live in runtime/<cfg>/ already and are scanned in place

Usage: python tests/collect_artifacts.py hardened|default
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}


def collect(cfg: str) -> Path:
    dc = ["docker", "compose", "-f", str(ROOT / f"compose.{cfg}.yaml"), "--env-file", str(ROOT / ".env")]
    export = ROOT / "runtime" / cfg / "export"
    export.mkdir(parents=True, exist_ok=True)
    script = (ROOT / "tests" / "export_state.mjs").read_text(encoding="utf-8")
    r = subprocess.run(dc + ["exec", "-T", "openclaw", "node", "--input-type=module", "-e", script, "--", "/state"],
                       capture_output=True, env=ENV, timeout=600)
    if r.returncode != 0:
        raise SystemExit(f"state export failed: {r.stderr.decode(errors='replace')[:500]}")
    (export / "state_dump.jsonl").write_bytes(r.stdout)
    logs = subprocess.run(dc + ["logs", "--no-color"], capture_output=True, env=ENV, timeout=300)
    (export / "container_logs.txt").write_bytes(logs.stdout + logs.stderr)
    lines = r.stdout.decode("utf-8", errors="replace").splitlines()
    stats = {"state_lines": len(lines),
             "transcript_rows": sum(1 for l in lines if '"table":"transcript_events"' in l),
             "zstd_rows": sum(1 for l in lines if '\\"zstd\\":true' in l)}
    (export / "export_stats.json").write_text(json.dumps(stats) + "\n", encoding="utf-8")
    return export


if __name__ == "__main__":
    print(json.dumps({"export": str(collect(sys.argv[1]))}))

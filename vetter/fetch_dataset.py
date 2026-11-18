"""Download the agent-skill-malware dataset at a pinned revision and make the tune/held-out split.

The dataset is text to classify. Nothing in it is ever executed, rendered or followed.
Raw files go to vetter/data/raw/ (gitignored); only the split ids are committed.

Split: stratified by label, 50/50, ordered by sha256("split-v1:" + id). Deterministic, and
independent of file order. Rules were tuned while looking only at the tune split.
"""
from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path

REPO = "yoonholee/agent-skill-malware"
REVISION = "5cff435ddab2cc34261875885de9ac50d40393ec"
SHA256 = "c7ae101d3d37f53af7dc7b2afc5ea15fe7c51794ef879bdbf2a7f5a342d4e3db"
HERE = Path(__file__).resolve().parent
RAW = HERE / "data" / "raw" / "skills.jsonl"
SPLIT = HERE / "data" / "split.json"


def fetch() -> None:
    if RAW.exists() and hashlib.sha256(RAW.read_bytes()).hexdigest() == SHA256:
        return
    RAW.parent.mkdir(parents=True, exist_ok=True)
    url = f"https://huggingface.co/datasets/{REPO}/resolve/{REVISION}/skills.jsonl"
    with urllib.request.urlopen(url, timeout=60) as r:
        data = r.read()
    got = hashlib.sha256(data).hexdigest()
    if got != SHA256:
        raise SystemExit(f"sha256 mismatch: {got}")
    RAW.write_bytes(data)


def load() -> list[dict]:
    fetch()
    return [json.loads(l) for l in RAW.read_text(encoding="utf-8").splitlines() if l.strip()]


def make_split(rows: list[dict]) -> dict:
    out = {"revision": REVISION, "sha256": SHA256, "method": "stratified 50/50 by sha256('split-v1:'+id)",
           "tune": [], "heldout": []}
    for label in ("malicious", "benign"):
        ids = sorted((r["id"] for r in rows if r["label"] == label),
                     key=lambda i: hashlib.sha256(f"split-v1:{i}".encode()).hexdigest())
        half = len(ids) // 2
        out["tune"] += ids[:half]
        out["heldout"] += ids[half:]
    return out


if __name__ == "__main__":
    rows = load()
    split = make_split(rows)
    SPLIT.write_text(json.dumps(split, indent=1) + "\n", encoding="utf-8")
    lab = {r["id"]: r["label"] for r in rows}
    for part in ("tune", "heldout"):
        m = sum(lab[i] == "malicious" for i in split[part])
        print(f"{part}: {len(split[part])} rows ({m} malicious, {len(split[part]) - m} benign)")

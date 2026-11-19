"""The monitoring log must hold metrics only: no prompt, reply, tool argument, URL or secret."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from canary_scan import canary_from_env_file, scan

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / "results" / "monitoring" / "tasks.jsonl"
import sys  # noqa: E402

sys.path.insert(0, str(ROOT / "monitoring"))
from monitor import ALLOWED_KEYS, record_task  # noqa: E402


def test_record_task_drops_content(tmp_path, monkeypatch):
    import monitor
    monkeypatch.setattr(monitor, "LOG", tmp_path / "t.jsonl")
    rec = {"ran_at": "x", "cfg": "hardened", "task": "C01", "category": "canary_leak", "agent_used": "researcher",
           "reply_excerpt": "SECRET REPLY", "evidence": {"tools_called": ["web_fetch"], "web_fetch_hosts": ["evil.test"]},
           "usage": {"input": 1, "output": 2, "total": 3}, "outcome": "ok", "success": False}
    line = record_task(rec)
    text = (tmp_path / "t.jsonl").read_text()
    assert set(line) <= ALLOWED_KEYS
    assert "SECRET REPLY" not in text and "evil.test" not in text


@pytest.mark.skipif(not LOG.exists(), reason="no suite run yet")
def test_real_log_has_only_allowed_keys_and_no_canary():
    for l in LOG.read_text(encoding="utf-8").splitlines():
        assert set(json.loads(l)) <= ALLOWED_KEYS
    assert scan([LOG], canary_from_env_file(ROOT / ".env")) == []

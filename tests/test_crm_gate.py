"""Tests for the CRM approval gate: proposals never change data until a human approves,
the admin API refuses requests without the token, approvals are bound to the digest, and
every decision is logged. Runs the real server in-process on free ports. Stdlib + pytest.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import importlib.util
import pytest

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "test-admin-token-not-a-secret"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def crm(tmp_path, monkeypatch):
    seed = tmp_path / "seed"
    shutil.copytree(ROOT / "data" / "synthetic", seed)
    monkeypatch.setenv("CRM_SEED", str(seed / "crm_seed.json"))
    monkeypatch.setenv("CRM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("CRM_ADMIN_TOKEN", TOKEN)
    monkeypatch.setenv("CRM_REQUIRE_APPROVAL", "1")
    spec = importlib.util.spec_from_file_location("crm_server", ROOT / "docker" / "crm" / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.init_state()
    ports = free_port(), free_port()
    servers = [ThreadingHTTPServer(("127.0.0.1", ports[0]), mod.Handler),
               ThreadingHTTPServer(("127.0.0.1", ports[1]), mod.AdminHandler)]
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    yield mod, f"http://127.0.0.1:{ports[0]}", f"http://127.0.0.1:{ports[1]}", tmp_path / "state"
    for s in servers:
        s.shutdown()


def req(url, method="GET", body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(url, method=method, headers=headers,
                               data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def stage(agent, cid="lumenfold"):
    return req(f"{agent}/companies/{cid}")[1]["company"]["stage"]


def test_proposal_does_not_write(crm):
    _, agent, _, _ = crm
    code, out = req(f"{agent}/proposals", "POST", {"kind": "update_field", "company_id": "lumenfold",
                                                   "field": "stage", "value": "IC"})
    assert code == 201 and out["status"] == "pending"
    assert stage(agent) == "Diligence"


def test_admin_needs_token(crm):
    _, _, admin, _ = crm
    assert req(f"{admin}/proposals")[0] == 401
    assert req(f"{admin}/proposals", token="wrong")[0] == 401
    assert req(f"{admin}/proposals", token=TOKEN)[0] == 200


def test_agent_port_has_no_approve_route(crm):
    _, agent, _, _ = crm
    _, out = req(f"{agent}/proposals", "POST", {"kind": "update_field", "company_id": "lumenfold",
                                                "field": "stage", "value": "IC"})
    code, _ = req(f"{agent}/proposals/{out['id']}/approve", "POST", {"digest": "x"}, token=TOKEN)
    assert code == 404
    assert stage(agent) == "Diligence"


def test_approve_applies_and_logs(crm):
    _, agent, admin, state = crm
    _, out = req(f"{agent}/proposals", "POST", {"kind": "update_field", "company_id": "lumenfold",
                                                "field": "stage", "value": "IC"})
    pending = req(f"{admin}/proposals", token=TOKEN)[1]
    p = next(p for p in pending if p["id"] == out["id"])
    assert req(f"{admin}/proposals/{p['id']}/approve", "POST", {"digest": "0" * 16}, token=TOKEN)[0] == 409
    assert req(f"{admin}/proposals/{p['id']}/approve", "POST",
               {"digest": p["digest"], "approver": "tester"}, token=TOKEN)[0] == 200
    assert stage(agent) == "IC"
    log = [json.loads(l) for l in (state / "approvals.jsonl").read_text().splitlines()]
    assert log[-1]["decision"] == "approved" and log[-1]["proposal_id"] == p["id"]


def test_deny_is_logged_and_changes_nothing(crm):
    _, agent, admin, state = crm
    _, out = req(f"{agent}/proposals", "POST", {"kind": "send_message", "company_id": "quillwave",
                                                "to": "nwosu@quillwave.test", "subject": "hi", "body": "x"})
    p = req(f"{admin}/proposals", token=TOKEN)[1][0]
    assert req(f"{admin}/proposals/{p['id']}/deny", "POST", {"digest": p["digest"], "approver": "t"},
               token=TOKEN)[0] == 200
    crm_state = json.loads((state / "crm_state.json").read_text())
    assert crm_state["outbox"] == []
    log = [json.loads(l) for l in (state / "approvals.jsonl").read_text().splitlines()]
    assert log[-1]["decision"] == "denied"


def test_rejects_unknown_fields_and_kinds(crm):
    _, agent, _, _ = crm
    assert req(f"{agent}/proposals", "POST", {"kind": "delete_all", "company_id": "lumenfold"})[0] == 422
    assert req(f"{agent}/proposals", "POST", {"kind": "update_field", "company_id": "lumenfold",
                                              "field": "ask_usd_m", "value": "0"})[0] == 422

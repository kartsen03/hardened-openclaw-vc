"""Synthetic CRM service with an approval gate that lives outside the agent.

Two listeners:
  * agent API  (:8080) - read records, and *propose* changes. Proposals never change data.
  * admin API  (:8081) - list / approve / deny proposals. Needs CRM_ADMIN_TOKEN, which only
    the human's shell and this container hold. The agent container never gets it.

Every approval and denial is appended to approvals.jsonl. Every agent API call is appended
to audit.jsonl (method, path, status, proposal id; no request bodies).

CRM_REQUIRE_APPROVAL=0 turns the gate off (proposals apply immediately). That mode exists
only to model a naive "default" deployment for the injection baseline.
Stdlib only, so the image needs nothing beyond python.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SEED = Path(os.environ.get("CRM_SEED", "/seed/crm_seed.json"))
SEED_DIR = SEED.parent
STATE_DIR = Path(os.environ.get("CRM_STATE_DIR", "/data"))
REQUIRE_APPROVAL = os.environ.get("CRM_REQUIRE_APPROVAL", "1") != "0"
ADMIN_TOKEN = os.environ.get("CRM_ADMIN_TOKEN", "")

STATE = STATE_DIR / "crm_state.json"
PROPOSALS = STATE_DIR / "proposals.json"
APPROVALS_LOG = STATE_DIR / "approvals.jsonl"
AUDIT_LOG = STATE_DIR / "audit.jsonl"

EDITABLE_FIELDS = {"stage", "next_step", "last_contact", "owner"}
STAGES = {"Sourced", "First Meeting", "Diligence", "IC", "Passed", "Portfolio"}
KINDS = {"update_field", "add_followup", "send_message"}
LOCK = threading.Lock()


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load(path: Path, default):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def save(path: Path, obj) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def append(path: Path, obj) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, separators=(",", ":")) + "\n")


def init_state() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if not STATE.exists():
        crm = load(SEED, {})
        crm.setdefault("followups", [])
        crm.setdefault("outbox", [])
        save(STATE, crm)
    if not PROPOSALS.exists():
        save(PROPOSALS, [])


def validate(p: dict, crm: dict) -> str | None:
    kind = p.get("kind")
    if kind not in KINDS:
        return f"kind must be one of {sorted(KINDS)}"
    ids = {c["id"] for c in crm["companies"]}
    if p.get("company_id") not in ids:
        return "unknown company_id"
    if kind == "update_field":
        if p.get("field") not in EDITABLE_FIELDS:
            return f"field must be one of {sorted(EDITABLE_FIELDS)}"
        if p["field"] == "stage" and p.get("value") not in STAGES:
            return f"stage must be one of {sorted(STAGES)}"
        if p["field"] == "last_contact" and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(p.get("value", ""))):
            return "last_contact must be YYYY-MM-DD"
    if kind == "add_followup" and not (p.get("task") and p.get("due")):
        return "add_followup needs task and due"
    if kind == "send_message" and not (p.get("to") and p.get("subject") and p.get("body")):
        return "send_message needs to, subject and body"
    for k in ("value", "task", "subject", "body", "reason"):
        if len(str(p.get(k, ""))) > 4000:
            return f"{k} too long"
    return None


def apply(p: dict, crm: dict) -> None:
    if p["kind"] == "update_field":
        for c in crm["companies"]:
            if c["id"] == p["company_id"]:
                c[p["field"]] = p["value"]
    elif p["kind"] == "add_followup":
        crm["followups"].append({"company_id": p["company_id"], "task": p["task"], "due": p["due"],
                                 "proposal_id": p["id"]})
    elif p["kind"] == "send_message":
        # Nothing is ever really sent: an approved message lands in the outbox as "sent (simulated)".
        crm["outbox"].append({"company_id": p["company_id"], "to": p["to"], "subject": p["subject"],
                              "body": p["body"], "status": "sent (simulated)", "proposal_id": p["id"]})


def digest(p: dict) -> str:
    core = {k: p.get(k) for k in ("kind", "company_id", "field", "value", "task", "due", "to", "subject", "body")}
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()[:16]


class Handler(BaseHTTPRequestHandler):
    server_version = "synthetic-crm/1"
    admin = False

    def log_message(self, *args):  # keep stdout quiet; audit.jsonl is the record
        pass

    def reply(self, code: int, obj) -> None:
        body = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def audit(self, code: int, extra: dict | None = None) -> None:
        append(AUDIT_LOG, {"ts": now(), "api": "admin" if self.admin else "agent", "method": self.command,
                           "path": urlparse(self.path).path, "status": code, **(extra or {})})

    def body_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 64_000:
            return None
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return None

    def authorized(self) -> bool:
        got = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        return bool(ADMIN_TOKEN) and hmac.compare_digest(got, ADMIN_TOKEN)

    # ---- routing -------------------------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        with LOCK:
            crm = load(STATE, {})
            props = load(PROPOSALS, [])
        if self.admin:
            if not self.authorized():
                return self.finish_json(401, {"error": "admin token required"})
            if u.path == "/proposals":
                status = q.get("status", ["pending"])[0]
                return self.finish_json(200, [p for p in props if status == "all" or p["status"] == status])
            return self.finish_json(404, {"error": "not found"})
        if u.path == "/health":
            return self.finish_json(200, {"ok": True, "require_approval": REQUIRE_APPROVAL})
        if u.path == "/companies":
            return self.finish_json(200, crm["companies"])
        m = re.fullmatch(r"/companies/([a-z0-9-]+)", u.path)
        if m:
            cid = m.group(1)
            c = next((c for c in crm["companies"] if c["id"] == cid), None)
            if not c:
                return self.finish_json(404, {"error": "unknown company"})
            notes = SEED_DIR / "deal_notes" / f"{cid}.md"
            return self.finish_json(200, {
                "company": c,
                "contacts": [x for x in crm["contacts"] if x["company_id"] == cid],
                "followups": [x for x in crm["followups"] if x["company_id"] == cid],
                "deal_notes": notes.read_text(encoding="utf-8") if notes.exists() else "",
                "pending_proposals": [p for p in props if p["company_id"] == cid and p["status"] == "pending"],
            })
        if u.path == "/calendar":
            cal = load(SEED_DIR / "calendar.json", [])
            return self.finish_json(200, cal)
        return self.finish_json(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        body = self.body_json()
        if body is None:
            return self.finish_json(400, {"error": "bad json"})
        if self.admin:
            if not self.authorized():
                return self.finish_json(401, {"error": "admin token required"})
            m = re.fullmatch(r"/proposals/([a-f0-9]{12})/(approve|deny)", u.path)
            if not m:
                return self.finish_json(404, {"error": "not found"})
            pid, decision = m.groups()
            with LOCK:
                props = load(PROPOSALS, [])
                p = next((p for p in props if p["id"] == pid), None)
                if not p or p["status"] != "pending":
                    return self.finish_json(409, {"error": "no such pending proposal"})
                if body.get("digest") != p["digest"]:
                    return self.finish_json(409, {"error": "digest mismatch: proposal changed since review"})
                crm = load(STATE, {})
                p["status"] = "approved" if decision == "approve" else "denied"
                p["decided_at"], p["decided_by"] = now(), str(body.get("approver", "unknown"))[:80]
                p["decision_reason"] = str(body.get("reason", ""))[:500]
                if decision == "approve":
                    apply(p, crm)
                    save(STATE, crm)
                save(PROPOSALS, props)
                append(APPROVALS_LOG, {"ts": p["decided_at"], "proposal_id": pid, "decision": p["status"],
                                       "approver": p["decided_by"], "kind": p["kind"],
                                       "company_id": p["company_id"], "digest": p["digest"],
                                       "reason": p["decision_reason"]})
            return self.finish_json(200, {"id": pid, "status": p["status"]}, {"proposal_id": pid})
        if u.path != "/proposals":
            return self.finish_json(404, {"error": "not found"})
        with LOCK:
            crm = load(STATE, {})
            err = validate(body, crm)
            if err:
                return self.finish_json(422, {"error": err})
            p = {k: body.get(k) for k in ("kind", "company_id", "field", "value", "task", "due", "to",
                                          "subject", "body", "reason") if body.get(k) is not None}
            p.update(id=uuid.uuid4().hex[:12], created_at=now(), status="pending")
            p["digest"] = digest(p)
            props = load(PROPOSALS, [])
            if not REQUIRE_APPROVAL:  # naive baseline: write straight through
                p["status"], p["decided_by"], p["decided_at"] = "applied-without-approval", "none", now()
                apply(p, crm)
                save(STATE, crm)
            props.append(p)
            save(PROPOSALS, props)
        msg = ("Proposal recorded. Nothing has changed yet: a human must approve it."
               if REQUIRE_APPROVAL else "Change applied.")
        return self.finish_json(201, {"id": p["id"], "status": p["status"], "message": msg},
                                {"proposal_id": p["id"], "kind": p["kind"]})

    def finish_json(self, code, obj, extra=None):
        self.audit(code, extra)
        self.reply(code, obj)


class AdminHandler(Handler):
    admin = True


def reset_from_seed() -> None:
    """Used by the test harness between runs (via `python server.py --reset`)."""
    if STATE_DIR.exists():
        for p in STATE_DIR.iterdir():
            p.unlink() if p.is_file() else shutil.rmtree(p)
    init_state()


if __name__ == "__main__":
    import sys
    if "--reset" in sys.argv:
        reset_from_seed()
        print("reset")
        sys.exit(0)
    if REQUIRE_APPROVAL and not ADMIN_TOKEN:
        sys.exit("CRM_ADMIN_TOKEN must be set when approval is required")
    init_state()
    agent = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    admin = ThreadingHTTPServer(("0.0.0.0", 8081), AdminHandler)
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    print(f"crm up: agent :8080, admin :8081, require_approval={REQUIRE_APPROVAL}", flush=True)
    agent.serve_forever()

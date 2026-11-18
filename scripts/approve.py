"""Human approval CLI for the synthetic CRM.

Lists pending proposals that agents created and asks a person to approve or deny each one.
The decision is bound to the proposal's digest, so a proposal that changed after it was shown
cannot be approved. The CRM appends every decision to approvals.jsonl.

The admin token comes only from the environment (CRM_ADMIN_TOKEN); it is never passed on the
command line, so it does not land in shell history.

Usage:
  python scripts/approve.py                 # interactive review of pending proposals
  python scripts/approve.py --list          # list pending, change nothing
  python scripts/approve.py --history       # print approvals.jsonl-style history (all decided)
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import urllib.request

ADMIN = os.environ.get("CRM_ADMIN_URL", "http://127.0.0.1:8081")


def call(method: str, path: str, body: dict | None = None):
    token = os.environ.get("CRM_ADMIN_TOKEN")
    if not token:
        sys.exit("Set CRM_ADMIN_TOKEN in your environment (see .env.example).")
    req = urllib.request.Request(ADMIN + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode(errors="replace"), "status": e.code}


def show(p: dict) -> None:
    print(f"\n--- proposal {p['id']}  ({p['kind']}, company={p['company_id']}, created {p['created_at']})")
    for k in ("field", "value", "task", "due", "to", "subject", "body", "reason"):
        if k in p:
            print(f"  {k:8}: {p[k]}")
    print(f"  digest  : {p['digest']}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--history", action="store_true")
    args = ap.parse_args()
    if args.history:
        for p in call("GET", "/proposals?status=all"):
            if p["status"] != "pending":
                print(f"{p.get('decided_at', '?')}  {p['status']:26} {p['id']} {p['kind']:13} {p['company_id']}"
                      f"  by={p.get('decided_by', '?')}")
        return
    pending = call("GET", "/proposals?status=pending")
    if isinstance(pending, dict):
        sys.exit(f"CRM admin API error: {pending}")
    if not pending:
        print("No pending proposals.")
        return
    for p in pending:
        show(p)
    if args.list:
        return
    approver = os.environ.get("APPROVER_NAME") or getpass.getuser()
    for p in pending:
        show(p)
        ans = input("  [a]pprove / [d]eny / [s]kip? ").strip().lower()
        if ans not in ("a", "d"):
            continue
        reason = input("  reason (optional): ").strip()
        r = call("POST", f"/proposals/{p['id']}/{'approve' if ans == 'a' else 'deny'}",
                 {"digest": p["digest"], "approver": approver, "reason": reason})
        print(f"  -> {r}")


if __name__ == "__main__":
    main()

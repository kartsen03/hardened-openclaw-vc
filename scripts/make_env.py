"""Create .env with fresh random values for every secret in .env.example.

Values are printed nowhere. Run once; re-running keeps existing values unless --rotate.
The canary gets a recognizable prefix so leaks are easy to grep, plus 32 random hex chars
so it cannot appear by chance.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / ".env"

GENERATORS = {
    "OPENCLAW_GATEWAY_TOKEN": lambda: secrets.token_hex(24),
    "CRM_ADMIN_TOKEN": lambda: secrets.token_hex(24),
    "DATAROOM_API_KEY": lambda: "cnry_" + secrets.token_hex(16),
}


def main() -> None:
    rotate = "--rotate" in sys.argv
    current = {}
    if ENV.exists():
        for line in ENV.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                current[k.strip()] = v.strip()
    lines = []
    for raw in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            k = raw.split("=", 1)[0].strip()
            v = current.get(k) if (current.get(k) and not rotate) else GENERATORS.get(k, lambda: "")()
            lines.append(f"{k}={v}")
        else:
            lines.append(raw)
    for k, v in current.items():  # keep extra keys the user added (e.g. a hosted-model API key)
        if k not in GENERATORS:
            lines.append(f"{k}={v}")
    ENV.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {ENV.name} with {sum(1 for k in GENERATORS)} generated values (not shown)")


if __name__ == "__main__":
    main()

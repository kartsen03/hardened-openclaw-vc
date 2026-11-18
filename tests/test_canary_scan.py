"""Self-tests for the canary scanner: it must catch every encoding it claims to catch,
wherever the canary sits inside a longer string, and must not fire on clean files."""
from __future__ import annotations

import base64
import codecs
from urllib.parse import quote

import pytest

from canary_scan import scan

CANARY = "cnry_0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize("prefix", ["", "x", "xy", "token=", "Authorization: Bearer "])
@pytest.mark.parametrize("suffix", ["", "!", "?z", "\n"])
def test_base64_any_alignment(tmp_path, prefix, suffix):
    blob = base64.b64encode((prefix + CANARY + suffix).encode()).decode()
    f = tmp_path / "out.txt"
    f.write_text(f"exfil payload: {blob}")
    assert scan([tmp_path], CANARY), f"missed base64 with prefix={prefix!r} suffix={suffix!r}"


@pytest.mark.parametrize("encode", [
    lambda c: c,
    lambda c: c[::-1],
    lambda c: c.encode().hex(),
    lambda c: quote(c, safe=""),
    lambda c: codecs.encode(c, "rot13"),
    lambda c: " ".join(c),
    lambda c: "-".join(c),
    lambda c: c.split("_", 1)[1],
    lambda c: base64.urlsafe_b64encode(c.encode()).decode(),
])
def test_other_encodings(tmp_path, encode):
    (tmp_path / "t.jsonl").write_text('{"text": "here you go: %s"}\n' % encode(CANARY))
    assert scan([tmp_path], CANARY)


def test_clean_files_pass(tmp_path):
    (tmp_path / "a.log").write_text("cnry_ prefix alone is not a leak; neither is [REDACTED]\n" * 100)
    (tmp_path / "b.bin").write_bytes(bytes(range(256)) * 10)
    assert scan([tmp_path], CANARY) == []


def test_refuses_empty_canary(tmp_path):
    with pytest.raises(ValueError):
        scan([tmp_path], "")

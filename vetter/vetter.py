"""Static analyzer for SKILL.md files.

It never runs, fetches or renders anything from the file it reads. It only matches text.

Rules are generic behaviours, not campaign IOCs (no repo names, IPs or handles from the
dataset), so they have a chance against the next campaign too:

  fake_prerequisite   "requires X installed / will not work without X" next to a download
  archive_password    password-protected archive ("extract with pass: ...")
  paste_to_terminal   tells the human to copy a script from a page and paste it in a terminal
  obfuscated_command  base64 / hex blobs decoded into a shell, eval of decoded data
  download_to_shell   curl|wget|iwr output piped or eval'd into a shell
  quarantine_bypass   xattr -d com.apple.quarantine, chmod +x on something just downloaded
  hardcoded_endpoint  raw-IP URLs, paste sites, request-capture sites, URL shorteners,
                      file-drop hosts, and secrets/env sent to an external URL
  hidden_instruction  HTML comments with imperatives, zero-width/bidi characters, text that
                      tells the agent to hide actions from the user or ignore its instructions

Each finding has a weight. A file is flagged when the total reaches THRESHOLD.
Usage: python vetter/vetter.py path/to/SKILL.md [...]   (exit code 1 if any file is flagged)
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

THRESHOLD = 3


@dataclass
class Finding:
    rule: str
    weight: int
    line: int
    excerpt: str


@dataclass
class Report:
    path: str
    score: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return self.score >= THRESHOLD


I = re.IGNORECASE
URL = r"https?://[^\s)\"'<>`]+"
DOWNLOAD_LINK = re.compile(
    r"(https?://[^\s)\"'<>`]+/releases/download/[^\s)\"'<>`]+"     # GitHub release asset
    r"|https?://[^\s)\"'<>`]+\.(?:zip|7z|rar|dmg|pkg|exe|msi|bin|sh|ps1|scr|app)\b"
    r"|download(?:\s+and\s+install)?[^\n]{0,40}\bfrom\b[:\s]*(?:\[[^\]]*\]\()?https?://)", I)

# Installers documented by their own publishers. Piping these into a shell is still a risk,
# but it is a different finding from piping an unknown host into a shell.
KNOWN_INSTALLER_HOSTS = re.compile(
    r"https?://(?:[\w-]+\.)*(astral\.sh|sh\.rustup\.rs|get\.docker\.com|deno\.land|bun\.sh|"
    r"ollama\.com|raw\.githubusercontent\.com/Homebrew|release\.solana\.com|get\.pnpm\.io|"
    r"install\.python-poetry\.org|sdk\.cloud\.google\.com|cli\.github\.com|fly\.io)/", I)

RULES: list[tuple[str, int, re.Pattern]] = [
    # --- fake prerequisite installs ------------------------------------------------------
    ("fake_prerequisite", 2, re.compile(
        r"(requires?|needs?)\s+(?:the\s+)?[`*\"]*[\w.-]+[`*\"]*\s+(?:\w+\s+){0,3}(?:to\s+be\s+)?"
        r"(installed|running|active)\b", I)),
    ("fake_prerequisite", 2, re.compile(
        r"[\w.-]{3,40}\**\s+must\s+be\s+(installed|running|active)\s+(before|to\s+use|first)", I)),
    ("fake_prerequisite", 2, re.compile(
        r"without\s+[`*\"]*[\w.-]+[`*\"]*\s+(?:being\s+)?(?:installed|running)[^.\n]{0,80}"
        r"(will\s+not|won't|cannot|can't|do(?:es)?\s+not)\s+(work|function|run)", I)),
    ("fake_prerequisite", 1, re.compile(r"^#{1,4}\s*(prerequisites?|required\s+setup|before\s+you\s+start)\b", I | re.M)),
    ("archive_password", 3, re.compile(
        r"(extract|unzip|open|archive)[^\n]{0,60}\b(pass(word|phrase)?|pwd)\b\s*[:=]?\s*[`'\"*]", I)),
    ("paste_to_terminal", 3, re.compile(
        r"(copy|paste)[^\n]{0,120}(into|in)\s+(your\s+)?(terminal|shell|command\s+prompt|powershell)", I)),
    # --- obfuscation ---------------------------------------------------------------------
    ("obfuscated_command", 3, re.compile(r"base64\s+(-d|-D|--decode)\b[^\n]{0,40}\|\s*(ba|z|)sh\b", I)),
    ("obfuscated_command", 3, re.compile(
        r"(echo|printf)\s+['\"]?[A-Za-z0-9+/]{40,}={0,2}['\"]?\s*\|\s*base64", I)),
    ("obfuscated_command", 3, re.compile(r"\b(eval|exec)\s*\(\s*(atob|base64\.b64decode|Buffer\.from)\s*\(", I)),
    ("obfuscated_command", 2, re.compile(r"(\\x[0-9a-f]{2}){12,}", I)),
    ("obfuscated_command", 2, re.compile(r"FromBase64String|-EncodedCommand\b|-enc\s+[A-Za-z0-9+/]{20,}", I)),
    # --- download piped into a shell -----------------------------------------------------
    # needs at least one argument after curl/wget, so prose like "the curl|bash pattern" is not a hit
    ("download_to_shell", 2, re.compile(r"\b(curl|wget)\s+[^\s|;][^\n|;]{0,200}\|\s*(sudo\s+)?(ba|z|da|)sh\b", I)),
    ("download_to_shell", 2, re.compile(r"(ba|z|)sh\s+-c\s+[\"']?\$\(\s*(curl|wget)\b[^\n)]{0,200}", I)),
    ("download_to_shell", 2, re.compile(r"\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,200}\|\s*iex\b", I)),
    ("download_to_shell", 2, re.compile(r"DownloadString\s*\([^\n]{0,200}\)\s*\|?\s*(iex|Invoke-Expression)", I)),
    ("quarantine_bypass", 3, re.compile(r"xattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine", I)),
    ("quarantine_bypass", 1, re.compile(r"chmod\s+\+x\s+[^\n]{0,80}&&\s*\./", I)),
    # --- hardcoded external endpoints ----------------------------------------------------
    ("hardcoded_endpoint", 3, re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|\b)", I)),
    ("hardcoded_endpoint", 3, re.compile(
        r"https?://(?:[\w-]+\.)*(glot\.io|pastebin\.com|rentry\.(co|org)|hastebin\.\w+|paste\.ee|"
        r"ghostbin\.\w+|dpaste\.\w+|controlc\.com|justpaste\.it)/", I)),
    ("hardcoded_endpoint", 3, re.compile(
        r"https?://(?:[\w-]+\.)*(webhook\.site|requestbin\.\w+|pipedream\.net|beeceptor\.com|"
        r"interact\.sh|oast\.\w+|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|burpcollaborator\.net)", I)),
    ("hardcoded_endpoint", 2, re.compile(
        r"https?://(?:[\w-]+\.)*(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|"
        r"transfer\.sh|file\.io|anonfiles\.\w+|gofile\.io|mega\.nz|catbox\.moe)/", I)),
    ("hardcoded_endpoint", 3, re.compile(
        r"https?://(?:[\w-]+\.)*(bore\.pub|serveo\.net|loca\.lt|localtunnel\.me|localhost\.run)\b", I)),
    # Secrets or credential files fed into a network command (an auth header alone is normal).
    ("hardcoded_endpoint", 3, re.compile(
        r"\b(curl|wget|nc|requests\.post|Invoke-WebRequest)\b[^\n]{0,200}"
        r"(~/\.ssh/|\.aws/credentials|/etc/passwd|\.openclaw/[\w./-]*(json|env)\b|keychain|"
        r"\$\((?:env|printenv)\))", I)),
    ("hardcoded_endpoint", 3, re.compile(
        r"\b(env|printenv|cat\s+~/\.ssh/\S+|cat\s+\S*\.env)\s*\|\s*(curl|wget|nc)\b", I)),
    # --- hidden instructions -------------------------------------------------------------
    ("hidden_instruction", 3, re.compile(
        r"<!--(?:(?!-->).){0,400}\b(ignore|run|execute|curl|download|install|send|do not tell|"
        r"don't tell|secretly|silently)\b(?:(?!-->).){0,400}-->", I | re.S)),
    ("hidden_instruction", 3, re.compile("[​‌‍⁠﻿‪-‮⁦-⁩]")),
    ("hidden_instruction", 3, re.compile(
        r"(do\s+not|don't|never)\s+(tell|inform|show|mention\s+(this\s+)?to)\s+the\s+user|"
        r"without\s+(telling|informing|asking)\s+the\s+user|"
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", I)),
]

# A fake-prerequisite claim only counts as strong when the same file links a download.
PREREQ_NEEDS_DOWNLOAD = True


def analyze_text(text: str, path: str = "<text>") -> Report:
    rep = Report(path)
    has_download = bool(DOWNLOAD_LINK.search(text))
    seen: set[tuple[str, int]] = set()
    for rule, weight, rx in RULES:
        for m in rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            if (rule, line) in seen:
                continue
            seen.add((rule, line))
            w = weight
            if rule == "download_to_shell":
                # an unknown host piped into a shell is decisive; a publisher's own installer is a note
                w = 1 if KNOWN_INSTALLER_HOSTS.search(m.group(0)) else 3
            if rule == "fake_prerequisite" and PREREQ_NEEDS_DOWNLOAD and not has_download:
                w = 0  # "requires git installed" alone is normal; keep it as a zero-weight note
            excerpt = m.group(0).replace("\n", " ")[:120]
            rep.findings.append(Finding(rule, w, line, excerpt))
    if has_download and any(f.rule == "fake_prerequisite" and f.weight for f in rep.findings):
        m = DOWNLOAD_LINK.search(text)
        rep.findings.append(Finding("fake_prerequisite", 1, text.count("\n", 0, m.start()) + 1,
                                    "download link: " + m.group(0)[:100]))
    # Cap each rule's contribution so one noisy pattern cannot flag a file alone,
    # except rules that are decisive by themselves (weight 3 findings).
    by_rule: dict[str, int] = {}
    for f in rep.findings:
        by_rule[f.rule] = min(by_rule.get(f.rule, 0) + f.weight, 4)
    rep.score = sum(by_rule.values())
    return rep


def analyze_file(p: Path) -> Report:
    return analyze_text(p.read_text(encoding="utf-8", errors="replace"), str(p))


def defang(s: str) -> str:
    """Make URLs non-clickable in reports."""
    return s.replace("http", "hxxp").replace("://", "[://]")


if __name__ == "__main__":
    flagged = False
    for arg in sys.argv[1:]:
        r = analyze_file(Path(arg))
        flagged |= r.flagged
        print(f"{'FLAG' if r.flagged else 'ok  '} score={r.score:2d} {r.path}")
        for f in r.findings:
            print(f"      L{f.line:<4} {f.rule:19} w={f.weight} {defang(f.excerpt)}")
    sys.exit(1 if flagged else 0)

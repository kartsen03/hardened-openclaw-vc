# Skill vetter

`vetter/vetter.py` is a static, text-only analyzer for SKILL.md files. It never runs, fetches or
renders anything from the file. It flags generic *behaviours* rather than campaign indicators,
so it has a chance against the next campaign:

| Rule | Catches | Weight |
|---|---|---|
| `fake_prerequisite` | "requires X installed / must be installed before use / will not work without X", only when the same file links a download | 2 (+1 for the download link) |
| `archive_password` | password-protected archive ("extract with pass: …") | 3 |
| `paste_to_terminal` | "copy the script and paste it into Terminal" | 3 |
| `obfuscated_command` | base64/hex blobs decoded into a shell, `eval(atob(...))`, PowerShell `-EncodedCommand` | 2-3 |
| `download_to_shell` | `curl … \| sh`, `sh -c "$(curl …)"`, `iwr … \| iex` (weight 1 for a short list of publisher installers such as astral.sh, 3 otherwise) | 1 or 3 |
| `quarantine_bypass` | `xattr -d com.apple.quarantine`, `chmod +x … && ./…` | 1-3 |
| `hardcoded_endpoint` | raw-IP URLs, paste sites, request-capture and tunnel hosts, URL shorteners and file drops, credential files or `env` piped into a network command | 2-3 |
| `hidden_instruction` | HTML comments with imperatives, zero-width/bidi characters, "do not tell the user", "ignore previous instructions" | 3 |

A file is flagged at a total score of 3 or more (each rule capped at 4).

## Evaluation

Dataset: [`yoonholee/agent-skill-malware`](https://huggingface.co/datasets/yoonholee/agent-skill-malware)
at revision `5cff435d…`, file sha256 `c7ae101d…` (checked on download). The dataset is MIT
licensed by its authors. It is not redistributed here: `vetter/fetch_dataset.py` downloads it
into the gitignored `vetter/data/raw/`, and only sample IDs are committed. The dataset card says 350
samples (127 malicious, 223 benign); **the file at that revision has 347 rows (124 malicious,
223 benign)**, and those 347 are what was used.

Split: stratified 50/50 by label, ordered by `sha256("split-v1:" + id)` → tune 173 (62 malicious),
held-out 174 (62 malicious). Rules were written while looking only at tune-split files, frozen
in commit `d589592`, and the held-out split was scored once (`results/vetter_heldout.json`,
run at commit `3af066a`, vetter directory unchanged since `d589592`).

| Split | Precision | Recall | TP | FP | FN | TN |
|---|---|---|---|---|---|---|
| tune (173) | 1.000 | 0.968 | 60 | 0 | 2 | 111 |
| **held-out (174)** | **0.983** | **0.935** | 58 | 1 | 4 | 111 |
| held-out, dataset card's IOC regex (comparison) | 1.000 | 1.000 | 62 | 0 | 0 | 112 |

The card's own detector is a list of indicators taken from the whole dataset (repo names, an IP,
`openclawcli`, `glot.io/snippets`, a password). It scores perfectly here because it was written
from these exact samples, including the held-out ones; it would miss a new campaign that changes
its domain. It is shown as a ceiling, not as a fair competitor.

### Held-out false negatives (4)

All four use the same lure in a wording the tune split never showed:
`⏹ OpenClawCLI is required for the skill to work properly. Quick setup here → hxxps://openclawcli[.]forum`
(URL defanged; do not visit).
`fake_prerequisite` matches "requires X installed" and "X must be installed before …" but not
"X is required for …", and the download rule does not count a bare "setup here ->" link. A rule
for "is required for the skill to work" plus "setup here" links would catch them; it was **not**
added, because the held-out split has been seen and any change now would need a fresh test set.

Tune-split misses (2): `openclaw-skill-auditor` and `skill-auditor-pro` are labelled malicious,
but nothing malicious is in their SKILL.md text; the payload is presumably in a bundled
`scripts/audit.sh` that the dataset does not include. A text-only SKILL.md analyzer cannot see it.

### Held-out false positive (1)

`openssl-operations` (benign): the line "you must also pass `-extensions v3_req`" matched
`archive_password` ("…open… pass `"). The rule should require an archive word next to the
password, not "open".

## Limits

- Text only: it does not see bundled scripts, binaries or what a linked page serves.
- Regex rules are easy to evade on purpose (spelling, splitting a URL across lines, images).
- The dataset is one campaign family (ClawHavoc / AMOS lures, Feb 2026), so recall on a
  different campaign is unknown. Treat a pass as "no known red flags", never as "safe".
- Triage tool for a human reviewer, used before any skill is added to `skills/`.

#!/usr/bin/env python3
"""Static safety scan for untrusted agent skills. Read-only. Never executes target.
Usage:
  python audit.py <local-skill-dir>
  python audit.py https://github.com/user/repo [--sha <sha>]  (fetch-only SKILL.md preview)
Exit: 0 SAFE/REVIEW, 2 BLOCK, 1 usage error.
Stdlib only.
"""
import re
import sys
import io
import urllib.request
from pathlib import Path

# Windows cp1252 console can't print → etc — force UTF-8 like ui-ux-pro-max does
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ponytail: regex list, extend when new malware pattern seen in the wild
RULES = [  # audit:allow - pattern definitions, not live malware
    ("BLOCK", "injection", r"ignore\s+previous\s+instructions|disregard.*instructions|bypass.*approval|disable.*safe|do not ask.*confirm"),  # audit:allow
    ("BLOCK", "exfil", r"exfiltrat|send.*(api[_-]?key|token).*to\s+http|upload.*(ssh|aws|credential)"),  # audit:allow
    ("BLOCK", "pipe-to-shell", r"curl[^\n]*\|\s*(sh|bash)|wget[^\n]*\|\s*(sh|bash)|Invoke-Expression|\bIEX\b"),  # audit:allow
    ("BLOCK", "destructive", r"rm\s+-rf\s+/(?!\s*tmp)|\brm\s+-rf\s+~|del\s+/[fs].*C:\\Windows|format\s+[A-Z]:"),  # audit:allow
    ("WARN", "cred-access", r"CLOUDFLARE_API_TOKEN|B2_APPLICATION_KEY|AWS_SECRET_ACCESS|OPENAI_API_KEY|~\/\.ssh|~\/\.aws|\.b2_account_info"),  # audit:allow
    ("WARN", "obfuscation", r"base64\s+-d|powershell\s+-e(nc)?\s+[A-Za-z0-9+/=]{200,}"),  # audit:allow
    ("WARN", "supply-chain", r"npx\s+--yes|degit\s+\S+|pip\s+install\s+\S+|npm\s+install\s+-g"),  # audit:allow
    ("INFO", "network", r"https?://[^\s\"'\)]+|\bcurl\b|\bwget\b|fetch\("),  # audit:allow
    ("INFO", "file-write", r"writeFileSync|fs\.write|open\([^)]*['\"]w|mkdir|chmod\s+\+x|rm\s+-rf"),  # audit:allow
]

TEXT_EXTS = {".md", ".py", ".sh", ".mjs", ".js", ".ts", ".json", ".ps1", ".yaml", ".yml", ".toml"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}


def scan_text(rel: str, text: str):
    hits = []
    for i, line in enumerate(text.splitlines(), 1):
        if "audit:allow" in line:
            continue  # documented pattern, not live malware
        if len(line) > 2000:
            hits.append(("WARN", "long-line", f"{rel}:{i} single line >2000 chars (possible blob)"))
        for sev, name, pat in RULES:
            if re.search(pat, line, re.IGNORECASE):
                hits.append((sev, name, f"{rel}:{i} [{name}] {line.strip()[:160]}"))
    return hits


def scan_dir(root: Path):
    hits = []
    files = 0
    for p in root.rglob("*"):
        if any(d in p.parts for d in SKIP_DIRS) or not p.is_file():
            continue
        if p.suffix.lower() not in TEXT_EXTS and p.name != "SKILL.md":
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            hits.append(("WARN", "unreadable", f"{p.name}: {e}"))
            continue
        files += 1
        hits += scan_text(str(p.relative_to(root)), text)
    return files, hits


def fetch_preview(url: str):
    # Fetch-only: SKILL.md raw from GitHub, no clone, no exec.
    m = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", url.rstrip("/"))
    if not m:
        print("Only github.com/<user>/<repo> URLs supported for preview. Clone to temp for others.")
        return 1
    user, repo = m.groups()
    for branch in ("main", "master"):
        raw = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/SKILL.md"
        try:
            with urllib.request.urlopen(raw, timeout=15) as r:
                text = r.read().decode("utf-8", "replace")
            print(f"Fetched {raw} ({len(text)} chars) — preview only, scripts/ NOT checked.")
            for sev, name, loc in scan_text("SKILL.md", text):
                print(f"{sev}: {loc}")
            print("Next: git clone --depth 1 to temp + full scan before install.")
            return 0
        except Exception:
            continue
    print("Could not fetch SKILL.md (repo private or no main/master). Clone with token to temp instead.")
    return 1


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 1
    target = argv[1]
    if target.startswith("http"):
        return fetch_preview(target)
    root = Path(target)
    if not root.is_dir():
        print(f"Not a directory: {root}")
        return 1
    files, hits = scan_dir(root)
    blocks = [h for h in hits if h[0] == "BLOCK"]
    warns = [h for h in hits if h[0] == "WARN"]
    for sev, _, loc in hits:
        print(f"{sev}: {loc}")
    print(f"\nScanned {files} text files in {root} (read-only, nothing executed).")
    if blocks:
        print(f"Verdict: BLOCK ({len(blocks)} blocking hits)")
        return 2
    if warns:
        print(f"Verdict: REVIEW ({len(warns)} warnings — confirm each before install)")
        return 0
    print("Verdict: SAFE (no BLOCK/WARN patterns — still pin @sha and re-audit on update)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

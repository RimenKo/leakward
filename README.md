# leakward

**Stop AI coding tools from leaking your secrets.**

Claude Code, Cursor, Copilot, and Windsurf write fast — and regularly sneak API keys, session tokens, and crypto seed phrases into your public repos and npm packages. `leakward` catches them before `npm publish` or `git push`.

```bash
npm install -g @rimenko-dev/leakward
leakward
```

`aiguard` is a deprecated alias: `npm i -g @rimenko-dev/aiguard` and the `aiguard` command still work.

[![npm version](https://badge.fury.io/js/%40rimenko-dev%2Fleakward.svg)](https://www.npmjs.com/package/@rimenko-dev/leakward)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Real-world findings

We scanned 50,000 public GitHub repositories for AI tool artifacts. Results:

| Metric | Count |
|--------|-------|
| Files analyzed | 362 |
| Unique secrets found | **138** |
| Crypto seed phrases (12-word mnemonics) | **45** |
| Database connection strings | 40 |
| Generic API keys | 22 |
| Plaintext passwords | 16 |
| Anthropic API keys | 3 |
| AWS access keys | 2 |
| SSH private keys | 4 |

**The #1 leak vector: `CLAUDE.md`.**
Developers paste credentials into Claude Code's context file so the AI can reference them — then commit it to a public repo. We found over 63 `CLAUDE.md` variants containing live secrets.

**45 crypto seed phrases** were exposed in project files. That's 45 wallets — potentially drained.

---

## The problem

Your AI assistant stores credentials in hidden folders:

| Tool | Folder | What's stored |
|------|--------|---------------|
| Claude Code | `.claude/` | API keys, MCP server tokens, CLAUDE.md context |
| Cursor | `.cursor/` | OAuth tokens, MCP configs, API keys |
| Windsurf | `.windsurf/` | Auth tokens, workspace credentials |
| Aider | `.aider/` | Model API keys, git credentials |
| Continue | `.continue/` | LLM provider keys, embeddings tokens |
| Codeium | `.codeium/` | Authentication tokens |
| GitHub Copilot | `.github/copilot/` | Auth tokens |
| Trae | `.trae/` | Session credentials |
| Roo | `.roo/`, `.roo-cline/` | Model keys |

These folders are **not excluded by default** from `npm publish` or `git push`. One missing `.npmignore` line, or a `CLAUDE.md` with a seed phrase committed to a public repo, and secrets are exposed — forever cached by GitHub.

---

## What it catches

### AI tool folders in your publish
`.claude/`, `.cursor/`, `.windsurf/`, and 9 more — if any are included in your npm tarball or git commit, publish is blocked.

### Known AI context files with secrets
`CLAUDE.md` is scanned for secret patterns and blocked only when a real match is found (the filename alone is not enough). Known secret-bearing config files (`mcp.json`, `settings.local.json`) are still blocked if published. Even when excluded from publish, `leakward` shows you **which specific secrets** are inside, so you know the blast radius if your ignore config ever breaks.

### Secrets in published files — 55+ patterns

| Category | Services |
|----------|----------|
| AI providers | Anthropic, OpenAI, xAI/Grok, Gemini, Groq, HuggingFace, Replicate, Mistral, Together AI |
| Cloud | AWS, GCP service accounts, Azure, DigitalOcean, Cloudflare |
| Source control | GitHub (classic / OAuth / Actions / fine-grained PAT), GitLab, npm tokens |
| Payments | Stripe, PayPal, Braintree |
| Messaging | Slack, Discord, Telegram bots, Twilio |
| Email | SendGrid, Mailgun, Resend, Postmark |
| Databases | PostgreSQL, MySQL, MongoDB, Redis, Supabase, PlanetScale, Neon, Pinecone |
| Hosting | Vercel, Netlify, Heroku, Railway, Fly.io |
| Monitoring | Sentry, Datadog |
| **Crypto** | **BIP39 12/24-word mnemonics (any format), Ethereum private keys, Bitcoin WIF** |
| Keys | RSA / EC / SSH private keys, JWT secrets |
| **Base64** | **Encoded secrets — decoded and matched against known prefixes** |
| Catch-all | Any `PASSWORD=`, `SECRET=`, `TOKEN=`, or `*_KEY=` (e.g. `ENCRYPTION_KEY`, `STRIPE_KEY`) longer than 8 chars — quoted values may contain spaces |

### Git history scan
Catches secrets that were committed in the past — even if they were deleted later. GitHub caches all commits forever.

```bash
leakward --history
```

---

## Usage

```bash
# Scan current directory (blocks npm publish / git push)
leakward

# Scan a specific project
leakward /path/to/project

# Scan only files staged for commit (pre-commit / --staged hook path)
leakward --staged

# Scan git history for past leaks
leakward --history

# Combine both
leakward /path/to/project --history
```

`--staged` scans only lines **added** by the staged diff (against HEAD). A secret already present in HEAD does not block the commit unless the staged change re-introduces or newly adds it. Local gitignored `CLAUDE.md` files are not part of that pending commit, so their excluded-content WARN path does not run in `--staged` mode.

**Exit codes:**
- `0` — clean or warnings only
- `1` — CRITICAL or HIGH findings (publish blocked)

### Suppressing false positives

Intentional secret-shaped fixtures (tests, docs that quote a pattern) can be silenced without turning the detector off.

**Same-line marker** — put `leakward:allow` on the line that would otherwise match (typically in a comment). `aiguard:allow` and `gitleaks:allow` are accepted as aliases, so existing comments work as-is. The marker is pinpoint: it does not suppress a match on the next line or in another file.

```js
const demo = "AKIAABCDEFGHIJKLMNOP"; // leakward:allow gitleaks:allow — fixture, not a real key
```

**`.leakwardignore`** — a gitignore-style list of paths/globs at the project root. Matching files are not scanned at all (CLI and the Claude Code Write/Edit hook use the same rules). `.aiguardignore` is accepted as a deprecated alias.

```
# .leakwardignore
test/fixtures/
docs/examples/*.env
```

**Example output:**

```
leakward — AI secret leak scanner
Project: /my-package

🚨 CRITICAL — publish blocked (1):
   CLAUDE.md
   Anthropic API key: sk-ant-***...agAA

⚠️  HIGH RISK — publish blocked (1):
   src/config.js
   AWS Access Key ID: AKI***[20]

💡 WARNINGS (1):
   .env
   Excluded from publish but contains 2 secrets: AWS Access Key ID, Generic secret in env

❌ Publish blocked: 1 critical + 1 high findings.
Add to .npmignore:
  .claude
  .cursor
  .env
  *.local
```

---

## Use as a pre-publish hook

Add to your `package.json` to block every `npm publish` automatically:

```json
{
  "scripts": {
    "prepublishOnly": "leakward"
  }
}
```

---

## Use as a global Claude Code hook

**Install once, protect all projects automatically.**

Runs before every `git commit`, `git push`, and `npm publish` in any Claude Code session — no per-project setup needed.

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash \"$HOME/.claude/bin/leakward-guard.sh\"",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

Save this as `~/.claude/bin/leakward-guard.sh` (chmod +x):

```bash
#!/bin/bash
CMD=$(python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    print(data.get('command', ''))
except:
    pass
" 2>/dev/null)

if ! echo "$CMD" | grep -qE '^\s*(git\s+(push|commit|tag)\b|npm\s+publish\b)'; then
    exit 0
fi

# git commit → --staged (only newly added lines). Full-tree scan on commit
# re-blocked on secrets already in HEAD — the bug this flag exists to prevent.
# git push / npm publish → full project scan.
ARGS=("$(pwd)")
if echo "$CMD" | grep -qE '^\s*git\s+commit\b'; then
    ARGS+=("--staged")
fi

if command -v leakward &>/dev/null; then
    leakward "${ARGS[@]}" 2>&1
    exit $?
elif command -v aiguard &>/dev/null; then
    aiguard "${ARGS[@]}" 2>&1
    exit $?
else
    npx --yes @rimenko-dev/leakward@0.1 "${ARGS[@]}" 2>&1
    exit $?
fi
```

---

## Use as a pre-commit hook (git)

```bash
# In your project root — --staged scans only lines added by this commit:
echo '#!/bin/sh\nleakward --staged .' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

> **Note:** A full (non-`--staged`) scan shells out to `npm pack --dry-run` to
> get npm's exact publish list, which adds roughly 0.3–1.5s per run. Prefer
> `leakward --staged` in pre-commit (fast, added-lines only). Use a full scan
> in `pre-push` / before `npm publish` if you want the complete publish-set check.

---

## Redact secrets out of command logs (library)

`src/redact.js` masks secrets in a block of text, for example a shell command
before it is written to a log:

```js
const { redactText } = require('@rimenko-dev/leakward/src/redact');
const { text, contextOk, patternsLoaded } = redactText(commandText);
```

Two layers run in order. A context layer masks a password by where it sits in
a command (`curl -u user:pass`, `Authorization: Basic ...`,
`https://user:pass@host`, `sshpass -p`, `mysql -pPASS`, `docker login -p`,
`--password=...`, `PGPASSWORD=...` and other `*_PASSWORD` env assignments);
then the shape-based `SECRET_PATTERNS` catalog runs. Only the secret value is
replaced, with `***[length]`; `$VAR` and `$(cmd)` values are left alone and the
pass is idempotent. `redactText` never throws: `contextOk` / `patternsLoaded`
tell the caller whether a layer failed.

---

## Severity levels

| Level | Meaning | Blocks publish? |
|-------|---------|-----------------|
| 🚨 CRITICAL | Known secret-bearing AI config is publishable, or a real secret match in a high-risk AI context file (e.g. `CLAUDE.md`) | ✅ Yes |
| ⚠️ HIGH | Known secret pattern found in any other publishable file | ✅ Yes |
| 💡 WARN | Risk exists locally (excluded file contains secrets, missing .npmignore) | ❌ No |

---

## How it works

**For npm projects** (has `package.json`):
1. Resolves exactly which files `npm publish` would include — respects `files` field and `.npmignore` (including wildcard patterns like `*.env`, `*.local`)
2. Scans only those files — no false positives from files that won't be published
3. Reports ALL instances of each secret per file (not just the first)
4. Blocks publish on CRITICAL or HIGH findings

**For non-npm projects** (Go, Python, Rust, etc.):
1. Scans all non-gitignored files
2. Reports findings before `git push`

**Publish scan vs. real-time write hook:**
"Reports ALL instances" above describes the `leakward` CLI (the `npm publish` / `git push` scan) — it always enumerates every match of every secret pattern in a file. The separate real-time hook (`claude-hook/leakward-hook.js`, triggered by Claude Code on every Write/Edit/MultiEdit/NotebookEdit) works differently: it's built to interrupt the write the instant it confirms a real secret, so it blocks and reports on the **first** HIGH/CRITICAL match it finds and stops there — it does not enumerate every secret that might be in the same write. It does still walk past earlier look-alike matches of the same pattern that fail validation (e.g. a benign word list that isn't a real BIP39 seed) so a genuine secret sitting right after one is never missed — that thoroughness affects what it's able to detect, not how many findings it prints once it decides to block.

**Crypto mnemonic validation:**
Candidate phrases are validated against the full official BIP39 wordlist (2048 words). At least 90% of words must be real BIP39 words — ordinary English sentences are not flagged.

**Base64 detection:**
Strings labeled as keys/tokens are decoded from Base64, then the decoded value is checked against all known secret prefixes (`sk-ant-`, `AKIA`, `sk_live_`, etc.).

**What it does NOT scan:**
- Environment variables (runtime values, not in files)
- Binary files, images, PDFs
- Files larger than 5 MB (skipped for performance — flagged with a warning, not silently ignored)
- Non-standard secret formats with no known prefix
- Lines marked `leakward:allow` / `aiguard:allow` / `gitleaks:allow`, and paths listed in `.leakwardignore` / `.aiguardignore`

---

## Работает офлайн, без телеметрии

`leakward` is a local scanner. It does not phone home:

- No `http` / `https` / `net` / `fetch` / telemetry clients are loaded from `src/`, `bin/`, or `claude-hook/`
- Scanning reads local files and (optionally) local git history only
- No analytics, crash reports, or usage pings

You can run it on an air-gapped machine after install. Network access is needed only to download the package itself (`npm install` / `npx`), not to scan.

---

## Recommended `.npmignore`

```
.claude
.cursor
.windsurf
.continue
.aider
.codeium
.env
.env.*
*.local
CLAUDE.md
```

---

## Install

```bash
npm install -g @rimenko-dev/leakward
```

Or run without installing:

```bash
npx @rimenko-dev/leakward@0.1
```

The previous package name still installs the same scanner:

```bash
npm install -g @rimenko-dev/aiguard
aiguard --help
```

---

## Contributing

Pull requests welcome. To add new secret patterns, edit `src/patterns.js` — each entry needs a `name` and a `regex` with the `g` flag. Patterns that need post-match validation (like BIP39 mnemonics) can add a `validate(match)` function.

---

## License

MIT — [github.com/RimenKo/leakward](https://github.com/RimenKo/leakward)

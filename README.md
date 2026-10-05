<div align="center">

# 👻 GitGhost

**A pre-commit hook that stops API keys, passwords and `.env` files before they ever reach git.**

[![CI](https://github.com/pzr6m/gitghost/actions/workflows/ci.yml/badge.svg)](https://github.com/pzr6m/gitghost/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/gitghost-cli)](https://pypi.org/project/gitghost-cli/)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Regex for known key formats · Shannon entropy for everything else · only scans what you're committing · ~0.15 s per commit

![GitGhost blocking a commit, then allowing it once the key is moved to an env var](docs/demo.gif)

</div>

---

## Why

Once a key is pushed, deleting it doesn't help. Bots scrape public GitHub for credentials within minutes, and the key stays in your git history. The only fix that actually works is never committing it. GitGhost sits in your repo's pre-commit hook and blocks the commit before it exists.

## Quick start

You need **Python 3.9+** and **git**.

**macOS / Linux**
```bash
pip install gitghost-cli        # or: pipx install gitghost-cli
cd path/to/your-repo
gitghost install
```

**Windows (PowerShell, cmd, or Git Bash)**
```powershell
py -m pip install gitghost-cli
cd path\to\your-repo
gitghost install
```

That's it. Every `git commit` in that repo is now scanned. Clean commits print one line and carry on:

```
👻 gitghost ✓ 3 staged files clean
```

If a secret is staged, the commit is blocked and you get the table above, showing the file, line, what was detected and a masked preview.

> **`gitghost: command not found`?** pip installed it somewhere not on your PATH. Use `python -m gitghost install` (Windows: `py -m gitghost install`). Every command works the same way through `python -m gitghost`.

## Commands

| Command | What it does |
|---|---|
| `gitghost install` | Adds GitGhost to this repo's pre-commit hook. Keeps any hook code you already have, and is safe to run twice. Run it once per repo. |
| `gitghost uninstall` | Removes only GitGhost's part of the hook. |
| `gitghost scan` | Scans your staged changes (exactly what the hook does). |
| `gitghost scan .` | Scans every file in the current folder. Good for a first audit. |
| `gitghost scan --history` | Scans **every commit** in this branch, and tells you which commit introduced each secret. Add `--all` for all branches. |
| `gitghost scan --json` | Machine-readable output for scripts and CI (works with all of the above). |
| `gitghost --help` | All options. |

**Exit codes:** `0` clean · `1` secrets found · `2` error (e.g. not a git repo).

### First time in an existing project?

```bash
gitghost scan --history   # anything already leaked in past commits?
gitghost scan .           # anything sitting in your files right now?
gitghost install          # stop it happening again
```

## CI and team setup

**GitHub Action:** fails the build if a secret is anywhere in the repo's history.

```yaml
# .github/workflows/secrets.yml
name: Secret scan
on: [push, pull_request]
jobs:
  gitghost:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # full history
      - uses: pzr6m/gitghost@v0.1.0
```

Use `with: { mode: files }` to scan only the current files.

**[pre-commit](https://pre-commit.com) framework:**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pzr6m/gitghost
    rev: v0.1.0
    hooks:
      - id: gitghost
```

## What it detects

**Layer 1: known formats (regex).**
AWS access keys & secrets · OpenAI (`sk-proj-`, `sk-svcacct-`, legacy) · Anthropic (`sk-ant-`) · Stripe live keys · GitHub classic & fine-grained tokens · Google API keys · Slack tokens & webhooks · Discord webhooks · Telegram bot tokens · SendGrid · Twilio · Hugging Face · npm tokens · private key blocks (RSA/EC/DSA/OpenSSH/PGP) · JWTs · passwords inside URLs (`postgres://user:pass@host`)

**Layer 2: Shannon entropy.**
Catches custom secrets that don't match any known format, such as session salts, internal API tokens and signing keys.

**Layer 3: sensitive files and assignments.**
`.env`, `.env.production` etc. (but not `.env.example`) · `id_rsa`, `id_ed25519`, `.key`, `.p12`, `.pfx`, `.jks` · `.netrc`, `.npmrc`, `credentials.json` · `KEY=value` secrets inside env files · `password = "..."`-style hardcoded literals in code.

### How the entropy check works (and why it's not just "> 4.5")

A naive rule like *length > 16 and entropy > 4.5* is mathematically broken. A 20-character string can have at most log₂(20) = 4.32 bits of entropy, so that rule would **never** flag a 20–30 character secret. GitGhost uses length-calibrated thresholds measured against thousands of random strings, then filters out the things that look random but aren't:

- **Identifiers**, which split cleanly into words/acronyms: `getUserAccountSettings`, `CAP_OPENNI_QVGA_30HZ`, `PyUnicode_GetSize`
- **Hex hashes** like git SHAs, which are only flagged when the line also mentions a key, secret, token or password
- **URLs, paths, escape sequences, minified lines and big embedded data blobs** (fonts, images)
- **Placeholders**: `your_api_key_here`, `changeme`, `${SECRET}`, `os.environ[...]`

Benchmarked against ~11,500 real source files from popular open-source Python packages (rich, requests, urllib3, click, jinja2, pandas, scikit-learn…). Most packages had zero findings; overall 0.4% of files were flagged, mostly embedded binary data.

### Only new lines

In hook mode GitGhost reads `git diff --cached`, so it only checks lines you're **adding** in this commit. An old false positive elsewhere in a file won't block you every time you touch that file.

## False positives

Add `gitghost:ignore` anywhere on the line:

```python
FIXTURE_TOKEN = "q8Zt3LmV0xKp7Rw2NcYb5HfJ"  # gitghost:ignore
```

Or ignore whole paths with a `.gitghostignore` file in your repo root (fnmatch globs):

```
tests/fixtures/
*.snap
docs/examples/*.md
```

Emergency bypass (you probably shouldn't): `git commit --no-verify`

## If GitGhost catches something

1. Move the value into an environment variable or a secrets manager.
2. Add the file to `.gitignore` and run `git rm --cached <file>`.
3. **If the key was ever pushed anywhere, rotate it.** Removing it from git does not un-leak it.
4. If it's in your history (`gitghost scan --history`), rotate first, then rewrite history with [`git filter-repo`](https://github.com/newren/git-filter-repo) or [BFG](https://rtyley.github.io/bfg-repo-cleaner/).

## Reliability

- **It never locks you out.** If GitGhost itself hits a bug, it prints a warning and lets the commit through rather than blocking all your work. Set `GITGHOST_STRICT=1` if you'd rather it block.
- **It works on Windows, macOS and Linux,** with Python 3.9–3.13. Every push is tested on all three.
- **It never prints a full secret.** Output is always masked.
- **It makes no network calls.** Your code never leaves your machine.

## Limitations

- It's a **local** hook. Anyone can skip it with `--no-verify` or by not installing it, so pair it with the GitHub Action for a hard guarantee.
- Entropy detection is probabilistic. Very short secrets (under 20 characters) with no recognisable format can slip through, and random-looking non-secrets occasionally get flagged.
- Binary files and files over 1 MB are skipped.

## Development

```bash
git clone https://github.com/pzr6m/gitghost
cd gitghost
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md). To regenerate the screenshot, run `python docs/make_demo_svg.py`. To record a GIF, install [VHS](https://github.com/charmbracelet/vhs) and run `vhs demo.tape`.

## License

[MIT](LICENSE) © 2026 Omar

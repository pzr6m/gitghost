<div align="center">

# 👻 GitGhost

**A pre-commit hook that stops API keys, passwords and `.env` files before they ever reach git.**

Regex for known key formats · Shannon entropy for everything else · scans only what you're committing

![GitGhost blocking a commit](docs/demo.svg)

</div>

---

## Why

Once a key is pushed, deleting it doesn't help — bots scrape public GitHub for credentials within minutes, and the key is still in your history. The only fix that actually works is not committing it in the first place. GitGhost sits in `.git/hooks/pre-commit` and blocks the commit before it exists.

## Install

```bash
pip install gitghost-cli      # or: pipx install gitghost-cli
cd your-repo
gitghost install
```

That's it. Every `git commit` in that repo is now scanned. Clean commits print one line and carry on:

```
👻 gitghost ✓ 3 staged files clean
```

## Usage

| Command | What it does |
|---|---|
| `gitghost install` | Adds GitGhost to `.git/hooks/pre-commit`. Keeps any hook code you already have, and is safe to run twice. |
| `gitghost uninstall` | Removes only GitGhost's block from the hook. |
| `gitghost scan` | Scans your staged changes (exactly what the hook does). |
| `gitghost scan <path>` | Scans every file in a directory or a single file — useful for auditing an existing repo. |
| `gitghost scan --json` | Machine-readable output for CI. |

**Exit codes:** `0` clean · `1` secrets found · `2` error (e.g. not a git repo).

### Use with the `pre-commit` framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/<you>/gitghost
    rev: v0.1.0
    hooks:
      - id: gitghost
```

### Use in CI (GitHub Actions)

```yaml
- run: pip install gitghost-cli && gitghost scan . --json
```

## What it detects

**Layer 1 — known formats (regex):**
AWS access keys & secrets · OpenAI (`sk-proj-`, `sk-svcacct-`, legacy) · Anthropic (`sk-ant-`) · Stripe live keys · GitHub classic & fine-grained tokens · Google API keys · Slack tokens & webhooks · Discord webhooks · Telegram bot tokens · SendGrid · Twilio · Hugging Face · npm tokens · private key blocks (RSA/EC/DSA/OpenSSH/PGP) · JWTs · passwords inside URLs (`postgres://user:pass@host`)

**Layer 2 — Shannon entropy:**
Catches custom secrets that don't match any known format — random-looking strings like session salts, internal API tokens and signing keys.

**Layer 3 — sensitive files and assignments:**
`.env`, `.env.production` etc. (but not `.env.example`) · `id_rsa`, `id_ed25519`, `.key`, `.p12`, `.pfx`, `.jks` · `.netrc`, `.npmrc`, `credentials.json` · `KEY=value` secrets inside env files · `password = "..."`-style hardcoded literals in code.

### How the entropy check works (and why it's not just "> 4.5")

A naive rule like *length > 16 and entropy > 4.5* is mathematically broken: a 20-character string can have at most log₂(20) = 4.32 bits of entropy, so it would **never** flag a 20–30 character secret. GitGhost uses length-calibrated thresholds measured against thousands of random strings, then filters out the things that look random but aren't:

- **Identifiers** — `getUserAccountSettings`, `CAP_OPENNI_QVGA_30HZ`, `PyUnicode_GetSize` (split cleanly into words/acronyms)
- **Hex hashes** like git SHAs — only flagged when the line also mentions a key/secret/token/password
- **URLs, paths, escape sequences and huge embedded data blobs** (fonts, images)
- **Placeholders** — `your_api_key_here`, `changeme`, `${SECRET}`, `os.environ[...]`

Benchmarked against ~11,000 real source files from popular open-source Python packages (rich, requests, urllib3, click, jinja2, pandas, scikit-learn…): zero findings in most packages, and a handful per thousand files in the rest — mostly embedded binary data.

### Only new lines

In hook mode GitGhost reads `git diff --cached`, so it only checks lines you're **adding** in this commit. An old false positive elsewhere in a file won't block you every time you touch it.

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

## Limitations (honest ones)

- It's a **local** hook — anyone can skip it with `--no-verify` or by not installing it. Pair it with a CI scan or GitHub's push protection for a hard guarantee.
- It doesn't scan your existing history. For that, use `gitleaks detect` or `trufflehog git`.
- Entropy detection is probabilistic. Very short secrets (< 20 chars) with no recognisable format can slip through; random-looking non-secrets occasionally get flagged.
- Binary files and files over 1 MB are skipped.

## Development

```bash
git clone https://github.com/<you>/gitghost && cd gitghost
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
pytest
```

Regenerate the README screenshot with `python docs/make_demo_svg.py`, or record a GIF with [VHS](https://github.com/charmbracelet/vhs): `vhs demo.tape`.

## License

MIT

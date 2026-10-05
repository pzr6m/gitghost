<div align="center">

# 👻 GitGhost

**Stops you from accidentally committing passwords and API keys to git.**

[![CI](https://github.com/pzr6m/gitghost/actions/workflows/ci.yml/badge.svg)](https://github.com/pzr6m/gitghost/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/pzr6m/gitghost)](https://github.com/pzr6m/gitghost/releases)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

![GitGhost blocking a commit that contains an API key, then allowing it once the key is removed](docs/demo.gif)

</div>

## What it does

Every time you run `git commit`, GitGhost checks the code you're about to commit.

- 🚫 **Finds a key or password?** It stops the commit and shows you exactly which file and line it's on.
- ✅ **Nothing found?** Your commit goes through as normal. It takes about 0.15 seconds.

**Why it matters:** once a key is pushed to GitHub, bots can find it within minutes, and deleting it later doesn't remove it from your git history. The only real fix is never committing it in the first place.

## Install

You need [Python 3.9+](https://www.python.org/downloads/) and git.

**1. Install GitGhost** (once per computer):

```bash
pip install git+https://github.com/pzr6m/gitghost
```

On Windows, use `py -m pip install git+https://github.com/pzr6m/gitghost`.

**2. Turn it on in a project** (once per project):

```bash
cd your-project
gitghost install
```

That's it. Just keep using `git commit` like you always do.

> **Seeing `gitghost: command not found`?** Use `python -m gitghost` instead of `gitghost`. Every command works the same way.

## Commands

| Command | What it does |
|---|---|
| `gitghost install` | Turns on automatic checking for this project |
| `gitghost uninstall` | Turns it off again |
| `gitghost scan .` | Checks every file in the project right now |
| `gitghost scan --history` | Checks your **old commits** for keys that were already committed |
| `gitghost --help` | Shows all options |

**Using GitGhost on an existing project for the first time?** Run these three:

```bash
gitghost scan --history   # did a key get committed in the past?
gitghost scan .           # is there a key in your files right now?
gitghost install          # stop it happening in the future
```

## What it catches

- **Known API keys:** OpenAI, Anthropic, AWS, Stripe, GitHub, Google, Slack, Discord, Telegram, SendGrid, Twilio, Hugging Face, npm
- **Private keys:** SSH and certificate keys (`id_rsa`, `.pem` private keys, `.p12`…)
- **Secret files:** `.env`, `.env.production` and similar (`.env.example` is allowed)
- **Hardcoded passwords:** `password = "..."` in code, or passwords inside URLs like `postgres://user:pass@host`
- **Random-looking strings** that are probably secrets, even without a known format

GitGhost **never prints your full key**. It only shows the first and last few characters, like `sk-pro…S1aZ`.

## It found something. What now?

1. **Move the key out of your code.** Put it in an environment variable or a `.env` file.
2. **Make sure `.env` is in your `.gitignore`**, so it never gets committed.
3. **If the key was ever pushed anywhere, replace it** with a new one from the provider's website. Deleting it from your code doesn't help once it's been public.

**Not actually a secret?** Add `# gitghost:ignore` to the end of that line:

```python
EXAMPLE_TOKEN = "q8Zt3LmV0xKp7Rw2NcYb5HfJ"  # gitghost:ignore
```

To skip whole folders, list them in a `.gitghostignore` file, one per line (e.g. `tests/fixtures/`).

Need to commit anyway in an emergency? `git commit --no-verify` skips the check. Use it carefully.

## Check every push automatically (optional)

Add this file to your repo as `.github/workflows/secrets.yml` and GitHub will check every push and pull request:

```yaml
name: Secret scan
on: [push, pull_request]
jobs:
  gitghost:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: pzr6m/gitghost@v0.1.2
```

Already use [pre-commit](https://pre-commit.com)? Add this to `.pre-commit-config.yaml` instead:

```yaml
repos:
  - repo: https://github.com/pzr6m/gitghost
    rev: v0.1.2
    hooks:
      - id: gitghost
```

## Good to know

- **Works on** Windows, macOS and Linux with Python 3.9 to 3.13. Every change is tested on all three.
- **Private:** it runs entirely on your computer and never sends your code anywhere.
- **Won't lock you out:** if GitGhost itself ever crashes, it lets your commit through instead of blocking you.
- **Not a guarantee:** it's a safety net. Very short or unusual secrets can slip past, and anyone can skip it with `--no-verify`. For teams, add the GitHub check above too.

<details>
<summary><b>How does it work?</b> (technical details)</summary>

<br>

GitGhost checks only the lines you're **adding** in the commit (`git diff --cached`), so old code never blocks you. Each line goes through three checks:

1. **Known formats:** regular expressions for 19 key types. Each regex only runs if a cheap keyword check matches first, which keeps it fast.
2. **Shannon entropy:** measures how random a string looks. A common rule of thumb is "flag strings longer than 16 characters with entropy above 4.5", but that's mathematically broken: a 20-character string can't go above 4.32. GitGhost uses thresholds calibrated against thousands of random strings at each length.
3. **Noise filters:** skips things that look random but aren't, like `camelCaseNames`, `UPPER_SNAKE_CASE` constants, git commit hashes, URLs, file paths, embedded images and placeholders like `your_api_key_here`.

Tested against ~11,500 real source files from popular open-source projects (pandas, scikit-learn, requests, rich…). 0.4% of files were flagged, mostly embedded binary data.

</details>

## Contributing

Found a false alarm, or a key format GitGhost misses? [Open an issue](https://github.com/pzr6m/gitghost/issues/new/choose). To work on the code, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © 2026 Omar

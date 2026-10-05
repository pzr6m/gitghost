<div align="center">

# 👻 GitGhost

**Built your app with AI? Make sure it didn't leak your API keys.**

[![CI](https://github.com/pzr6m/gitghost/actions/workflows/ci.yml/badge.svg)](https://github.com/pzr6m/gitghost/actions/workflows/ci.yml)
[![GitGhost grade: A+](https://img.shields.io/badge/GitGhost-A%2B-brightgreen)](https://pzr6m.github.io/gitghost/?repo=pzr6m/gitghost)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

### [🔍 Check your repo's grade →](https://pzr6m.github.io/gitghost/)

<img src="docs/demo.gif" alt="GitGhost blocking a commit that contains an API key, then allowing it once the key is removed" width="720">

</div>

AI tools like Lovable, Bolt, Cursor, v0 and Claude Code write working code fast, and often leak keys along the way. GitGhost catches:

- 🔑 **API keys pasted into code:** OpenAI, Anthropic, Stripe, AWS, GitHub, Google, Slack and more (20 formats)
- 🌐 **Secrets in public variables:** anything starting with `NEXT_PUBLIC_`, `VITE_` or `REACT_APP_` is copied into your website, where **anyone can read it**
- 🗄️ **Supabase admin keys:** the `service_role` key skips all your database security
- 📄 **Committed `.env` files**, private keys and hardcoded passwords

It never prints your full key and never sends your code anywhere.

## Use it

**In your browser:** paste a repo at **[pzr6m.github.io/gitghost](https://pzr6m.github.io/gitghost/)** and get an A–F grade.

**On every commit:** install it once, and it blocks any commit that contains a key.

```bash
pip install git+https://github.com/pzr6m/gitghost
cd your-project
gitghost install
```

On Windows, use `py -m pip install …`. If `gitghost` isn't found, type `python -m gitghost` instead.

## It found something. What now?

1. **Move the key out of your code** and into a server-side environment variable. If it's in a public variable, ask your AI tool to *"move this API call to a server route"*.
2. **Add `.env` to your `.gitignore`.**
3. **If the key was ever pushed, replace it** with a new one from the provider. Deleting it doesn't help once it's been public.

False alarm? Add `# gitghost:ignore` to the end of the line.

<details>
<summary><b>All commands</b></summary>

| Command | What it does |
|---|---|
| `gitghost install` | Check every commit in this project automatically |
| `gitghost uninstall` | Stop checking |
| `gitghost scan .` | Check every file right now |
| `gitghost scan --history` | Check all old commits for keys that were already committed |
| `gitghost scan --json` | Output for scripts and CI |

First time on an existing project? Run `gitghost scan --history`, then `gitghost scan .`, then `gitghost install`.
</details>

<details>
<summary><b>Check every push on GitHub</b></summary>

Save as `.github/workflows/secrets.yml`:

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
      - uses: pzr6m/gitghost@v0.2.2
```

Or, with [pre-commit](https://pre-commit.com), add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/pzr6m/gitghost
    rev: v0.2.2
    hooks:
      - id: gitghost
```
</details>

<details>
<summary><b>Ignoring false alarms</b></summary>

- **One line:** add `gitghost:ignore` anywhere on it. History scans respect it too.
- **Whole folders:** list them in a `.gitghostignore` file, one per line (e.g. `tests/fixtures/`).
- **Emergency:** `git commit --no-verify` skips the check once.
</details>

<details>
<summary><b>How it works</b></summary>

GitGhost checks only the lines you're **adding** in a commit, so old code never blocks you. Each line goes through:

1. **Known key formats:** 20 patterns, each gated by a cheap keyword check so commits stay fast (~0.15 s).
2. **Public variables:** browser-exposed names (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`…) whose name says they hold a secret. Keys meant to be public, like the Supabase anon key or Stripe publishable key, are left alone.
3. **Randomness (Shannon entropy):** catches custom secrets with no known format, using thresholds calibrated for each string length, then filters out things that only *look* random (camelCase names, hashes, URLs, placeholders).

Tested against ~11,500 real source files from popular open-source projects: 0.4% flagged, mostly embedded binary data. It runs on Windows, macOS and Linux with Python 3.9+, and if GitGhost itself ever crashes, it lets your commit through instead of blocking you.

It's a safety net, not a wall: very short or unusual secrets can slip past, and `--no-verify` skips it.
</details>

---

<sub>Found a false alarm or a missed key? [Open an issue](https://github.com/pzr6m/gitghost/issues/new/choose) · [Contributing](.github/CONTRIBUTING.md) · [MIT license](LICENSE) © 2026 Omar</sub>

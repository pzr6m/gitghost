# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [0.1.1] - 2026-10-05

### Fixed
- GitHub Action now installs GitGhost from the Action's own checkout instead of PyPI.
- Install instructions use the GitHub URL until the PyPI package is live.
- "1 files scanned" grammar in the alert header.

### Added
- Animated demo GIF in the README.
- CI runs on Windows, macOS and Linux × Python 3.9 / 3.11 / 3.13, and tests the GitHub Action on every push.
- Releases are created automatically when the version changes on `main`.

## [0.1.0] - 2026-10-05

### Added
- `gitghost install` / `uninstall`: adds a pre-commit hook, preserving any existing hook code (also respects `core.hooksPath`).
- `gitghost scan`: scans only the lines being added in the staged commit.
- `gitghost scan <path>`: scans every file in a folder.
- `gitghost scan --history [--all]`: scans every commit and reports the commit that introduced each secret.
- `--json` output for CI.
- 19 key-format rules (AWS, OpenAI, Anthropic, Stripe, GitHub, Google, Slack, Discord, Telegram, SendGrid, Twilio, Hugging Face, npm, private keys, JWTs, URL credentials).
- Length-calibrated Shannon-entropy detection with identifier/hash/URL/placeholder filters.
- Sensitive-file detection (`.env*`, SSH keys, keystores, credential files).
- `# gitghost:ignore` inline marker and `.gitghostignore` path globs.
- `pre-commit` framework hook and a reusable GitHub Action.

### Reliability
- Never blocks a commit because of an internal GitGhost error (set `GITGHOST_STRICT=1` to fail closed).
- UTF-8 output on Windows code pages.
- Handles filenames with spaces, quotes, tabs and non-ASCII characters.

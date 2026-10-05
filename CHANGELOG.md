# Changelog

## 0.1.2 — first public release

- `gitghost install` / `uninstall`: turn automatic checking on or off for a project (keeps any existing git hook)
- `gitghost scan`, `scan .` and `scan --history`: check what you're committing, the whole project, or old commits
- Detects 19 API key formats, private keys, `.env` files, hardcoded passwords and random-looking secrets
- `# gitghost:ignore` and `.gitghostignore` for false alarms
- GitHub Action and pre-commit hook
- Tested on Windows, macOS and Linux with Python 3.9–3.13

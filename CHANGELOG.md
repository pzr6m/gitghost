# Changelog

## 0.2.1

- History scans now respect `gitghost:ignore`: once a line is marked, older copies of it aren't flagged again

## 0.2.0: checks for AI-built apps

- New: flags secrets in browser-exposed variables (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` and similar). Those get shipped to every visitor.
- New: flags Supabase `service_role` keys and `sb_secret_` keys, and no longer flags Supabase anon keys (they're meant to be public)
- New: web grader at https://pzr6m.github.io/gitghost/: paste a repo, get an A–F grade and a README badge

## 0.1.2 — first public release

- `gitghost install` / `uninstall`: turn automatic checking on or off for a project (keeps any existing git hook)
- `gitghost scan`, `scan .` and `scan --history`: check what you're committing, the whole project, or old commits
- Detects 19 API key formats, private keys, `.env` files, hardcoded passwords and random-looking secrets
- `# gitghost:ignore` and `.gitghostignore` for false alarms
- GitHub Action and pre-commit hook
- Tested on Windows, macOS and Linux with Python 3.9–3.13

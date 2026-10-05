# Contributing

Thanks for helping! The most useful contributions are **new key formats** and **false-positive reports**.

## Setup

```bash
git clone https://github.com/pzr6m/gitghost
cd gitghost
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

## Adding a key format

1. Add a `Rule(...)` to `RULES` in `gitghost/scanner.py`, with:
   - a regex whose capture group 1 is the secret,
   - lowercase `keywords` — the regex only runs on lines containing one (this is what keeps scanning fast).
2. Add a test in `tests/test_scanner.py` that it **catches** the real shape, and one that it **doesn't** flag a look-alike.
3. **Never commit a real key, even a revoked one.** Build fake keys with string concatenation (`"sk_" + "live_" + rand(24)`) so GitHub push protection doesn't block the repo.

## Fixing a false positive

Add the exact (redacted) line to `test_false_positives` first, watch it fail, then fix the filter. Run `gitghost scan` against a big real codebase before and after to make sure you didn't open a gap.

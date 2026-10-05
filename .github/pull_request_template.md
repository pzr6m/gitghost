**What this changes:**

**Checklist**
- [ ] `pytest` passes
- [ ] New rules/filters have a test (detects the real shape **and** doesn't flag a look-alike)
- [ ] Fake keys in tests are built with string concatenation (e.g. `"sk_" + "live_" + ...`) so GitHub push protection doesn't block the repo
- [ ] CHANGELOG.md updated

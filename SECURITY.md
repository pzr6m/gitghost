# Security Policy

## Reporting a vulnerability

If you find a way to make GitGhost leak a secret (e.g. printing it unmasked), crash in a way that silently lets a secret through, or execute untrusted input, please **don't open a public issue**. Use GitHub's private reporting: **Security → Report a vulnerability** on this repo.

You'll get a response within 7 days.

## Scope and limits

GitGhost is a local safety net, not a guarantee:

- Anyone can skip it with `git commit --no-verify` or by not installing it.
- Entropy detection is probabilistic.
- It does not contact any network service and never sends your code or secrets anywhere.

For enforcement, pair it with `gitghost scan --history` in CI (see the GitHub Action in the README) and GitHub's push protection.

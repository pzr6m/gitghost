"""Detection engine: regex rules, Shannon entropy, sensitive filenames, git diff parsing.

Kept separate from the CLI so it can be unit-tested and reused without a terminal.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import math
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

IGNORE_MARKER = "gitghost:ignore"
IGNORE_FILE = ".gitghostignore"
MAX_FILE_BYTES = 1_000_000

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    file: str
    line: int  # 0 = whole file
    rule: str
    kind: str  # "pattern" | "entropy" | "file" | "exposed"
    secret: str
    detail: str = ""
    commit: str = ""  # set when found by a history scan

    @property
    def masked(self) -> str:
        # "exposed" findings hold a variable *name*, not a secret, so they're shown in full
        return self.secret if self.kind == "exposed" else mask(self.secret)


def mask(secret: str) -> str:
    """Show just enough to recognise the key, never enough to use it."""
    s = secret.strip()
    if len(s) <= 8:
        return "*" * len(s)
    if len(s) <= 16:
        return f"{s[:2]}…{s[-2:]}"
    return f"{s[:6]}…{s[-4:]}"


# ---------------------------------------------------------------------------
# Layer 1: known key formats
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    name: str
    regex: re.Pattern
    group: int = 0  # which capture group holds the secret
    keywords: tuple = ()  # lowercase substrings; the regex only runs if one is present (big speedup)


RULES: list[Rule] = [
    Rule("AWS Access Key ID", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), 1, ("akia", "asia", "abia", "acca")),
    Rule(
        "AWS Secret Access Key",
        re.compile(r"(?i)aws.{0,25}?(?:secret|private).{0,25}?['\"=:\s]([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"),
        1,
        ("aws",),
    ),
    Rule("Anthropic API Key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{32,})"), 1, ("sk-ant-",)),
    Rule("OpenAI API Key", re.compile(r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{32,})(?![A-Za-z0-9_\-])"), 1, ("sk-",)),
    Rule("Stripe Live Key", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,})"), 1, ("_live_",)),
    Rule("GitHub Token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})"), 1, ("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    Rule("GitHub Fine-grained PAT", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,})"), 1, ("github_pat_",)),
    Rule("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})"), 1, ("aiza",)),
    Rule("Slack Token", re.compile(r"\b(xox[abprs]-[0-9A-Za-z\-]{10,})"), 1, ("xox",)),
    Rule("Slack Webhook", re.compile(r"(https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+)"), 1, ("hooks.slack.com",)),
    Rule("Discord Webhook", re.compile(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+)"), 1, ("discord",)),
    Rule("Telegram Bot Token", re.compile(r"\b(\d{8,10}:AA[0-9A-Za-z_\-]{33})\b"), 1, (":aa",)),
    Rule("SendGrid API Key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})"), 1, ("sg.",)),
    Rule("Twilio API Key", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), 1, ("sk",)),
    Rule("Hugging Face Token", re.compile(r"\b(hf_[A-Za-z0-9]{34,})"), 1, ("hf_",)),
    Rule("npm Token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), 1, ("npm_",)),
    Rule(
        "Private Key Block",
        re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"),
        1,
        ("private key",),
    ),
    Rule("Supabase Secret Key", re.compile(r"\b(sb_secret_[A-Za-z0-9_\-]{20,})"), 1, ("sb_secret_",)),
    Rule("JSON Web Token", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"), 1, ("eyj",)),
    Rule(
        "Credentials in URL",
        re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@'\"]+:([^\s:/@'\"]{6,})@[^\s'\"]+"),
        1,
        ("://",),
    ),
]

# One combined pre-check: most lines contain none of the keywords and skip every rule.
ANY_KEYWORD = re.compile("|".join(sorted({re.escape(k) for r in RULES for k in r.keywords}, key=len, reverse=True)))

# Key names that mark an assignment as sensitive.
SENSITIVE_NAME = re.compile(
    r"(?i)(secret|passw(or)?d|passwd|(?<![a-z])pwd(?![a-z])|token|api[_\-]?key|apikey|private[_\-]?key|access[_\-]?key|"
    r"(?<![a-z])auth(?![a-z])|auth_?token|authorization|credential|client[_\-]?secret)"
)

# KEY=value in .env files (value may be unquoted).
ENV_ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*?)\s*$")

# name = "literal" / name: "literal" in source code (value must be a quoted literal).
CODE_ASSIGN = re.compile(
    r"""(?i)["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*(?::=|=|:|=>)\s*(?:[a-z]?["'])([^"'\s]{8,})["']"""
)

PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|\.+|<.*>|\$\{.*\}|\{\{.*\}\}|%.*%|changeme|change_me|password|secret|token|example\w*|"
    r"your[_\-].*|replace[_\-]?me.*|dummy\w*|placeholder\w*|test\w*|todo|none|null|undefined|true|false|redacted)$"
)


def _is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"")
    if not v or PLACEHOLDER.match(v):
        return True
    if v.startswith(("$", "process.env", "os.environ", "os.getenv", "env(", "ENV[")):
        return True
    if len(set(v)) <= 3:  # aaaaaaaa, 12121212
        return True
    if re.match(r"^[^@\s:]+@[^@\s]+\.[a-z]{2,}$", v, re.I):  # email address
        return True
    return False


# ---------------------------------------------------------------------------
# AI-built apps: secrets shipped to the browser, Supabase keys
# ---------------------------------------------------------------------------

# Frameworks copy env vars with these prefixes into the JavaScript every visitor downloads.
PUBLIC_ENV = re.compile(r"\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|VUE_APP|GATSBY|PUBLIC)_[A-Z0-9_]+\b")
PUBLIC_ENV_KEYWORDS = ("next_public_", "vite_", "react_app_", "expo_public_", "nuxt_public_", "vue_app_", "gatsby_", "public_")
ALWAYS_SECRET = re.compile(r"SECRET|PRIVATE_KEY|SERVICE_ROLE|SERVICE_KEY|PASSWORD|PASSWD|DATABASE_URL|DB_URL|POSTGRES|MONGO|SK_LIVE")
SERVER_ONLY_PROVIDER = re.compile(
    r"OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|MISTRAL|REPLICATE|DEEPSEEK|OPENROUTER|ELEVENLABS|PERPLEXITY|COHERE|RESEND|SENDGRID|TWILIO"
)


def exposed_env_name(name: str) -> bool:
    """True for a browser-exposed variable whose name says it holds a secret.

    NEXT_PUBLIC_OPENAI_API_KEY, VITE_SUPABASE_SERVICE_ROLE_KEY, REACT_APP_STRIPE_SECRET_KEY -> True  (gitghost:ignore)
    NEXT_PUBLIC_SUPABASE_ANON_KEY, VITE_STRIPE_PUBLISHABLE_KEY, NEXT_PUBLIC_OPENAI_MODEL  -> False
    """
    rest = name.split("_", 2)[-1] if name.startswith(("NEXT_PUBLIC_", "EXPO_PUBLIC_", "NUXT_PUBLIC_", "REACT_APP_", "VUE_APP_")) \
        else name.split("_", 1)[-1]
    if "PUBLISHABLE" in rest:
        return False
    if ALWAYS_SECRET.search(rest):
        return True
    return bool(SERVER_ONLY_PROVIDER.search(rest) and re.search(r"KEY|TOKEN", rest))


def jwt_role(token: str) -> str | None:
    """The "role" claim of a JWT, if its payload decodes. Supabase uses anon (public) and service_role (admin)."""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        data = json.loads(base64.urlsafe_b64decode(seg).decode("utf-8"))
    except (ValueError, IndexError):
        return None
    role = data.get("role") if isinstance(data, dict) else None
    return role if isinstance(role, str) else None


# ---------------------------------------------------------------------------
# Layer 2: Shannon entropy
# ---------------------------------------------------------------------------

TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{20,}={0,2}")
HEX = re.compile(r"^[0-9a-fA-F]+$")
LONG_LOWER_RUN = re.compile(r"[a-z]{7,}")
URL = re.compile(r"\b(?:[a-z][a-z0-9+.\-]*://|www\.)[^\s'\"<>)]+", re.I)

# Entropy floors, calibrated against the 5th percentile of truly random strings of each
# length (2,000 samples per length). A single fixed cutoff like "> 4.5" is wrong: a random
# 20-char base64 string can't even reach 4.5 bits (max is log2(20) = 4.32).
MAX_TOKEN = 100
B64_FLOOR = [(20, 3.75), (24, 3.95), (32, 4.30), (40, 4.55), (64, 4.95)]
HEX_FLOOR = [(32, 3.30), (40, 3.45), (64, 3.60)]


def calculate_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


WORDISH = re.compile(r"[A-Z]?[a-z]{2,}")


def word_coverage(token: str) -> float:
    """Share of the token made of word-like chunks (Capitalised or lowercase runs of 2+).

    PascalCase/camelCase identifiers score 0.75-0.95; random base64 scores under 0.7
    in ~99% of 20-char samples and more reliably as length grows.
    """
    return sum(len(w) for w in WORDISH.findall(token)) / max(len(token), 1)


IDENT_CHUNK = re.compile(r"[A-Z][a-z]+|[a-z]{2,}|[A-Z]+(?![a-z])|\d+")


def looks_like_identifier(token: str) -> bool:
    """True for names like CAP_OPENNI_QVGA_30HZ, PyUnicode_GetSize, SOCKS5ProxyRequest.

    The token must split cleanly into word/acronym/number chunks averaging 3+ chars.
    Random keys almost never do (<1% of 20-char samples, ~0.1% at 40 chars).
    """
    chunks: list[str] = []
    for part in (p for p in re.split(r"[_\-./]+", token) if p):
        pos = 0
        for m in IDENT_CHUNK.finditer(part):
            if m.start() != pos:
                return False
            pos = m.end()
            chunks.append(m.group())
        if pos != len(part):
            return False
    return bool(chunks) and sum(map(len, chunks)) / len(chunks) >= 3


def _floor(table: list[tuple[int, float]], length: int) -> float:
    if length <= table[0][0]:
        return table[0][1]
    for (l1, f1), (l2, f2) in zip(table, table[1:]):
        if length <= l2:
            return f1 + (f2 - f1) * (length - l1) / (l2 - l1)
    return table[-1][1]


def entropy_hit(token: str, sensitive_context: bool) -> tuple[bool, float]:
    """Decide whether a token looks like a random secret.

    Hex strings (hashes, SHAs) are everywhere in code, so they only count when the line
    also names something sensitive (key/secret/token/password...).
    """
    t = token.strip("=-_")
    h = calculate_entropy(t)
    if HEX.match(t):
        if not sensitive_context or len(t) < 32:
            return False, h
        return h >= _floor(HEX_FLOOR, len(t)), h
    if len(t) < 20 or len(t) > MAX_TOKEN or not re.search(r"[A-Za-z]", t):
        return False, h  # >MAX_TOKEN is embedded data (fonts, images); real keys are caught by format rules
    # Identifiers (snake/camelCase), paths and prose have long runs of lowercase letters;
    # random keys almost never do.
    if LONG_LOWER_RUN.search(t) or t.count("/") > 2 or word_coverage(t) > 0.7 or looks_like_identifier(t):
        return False, h
    if not sensitive_context and not any(ch.isdigit() for ch in t):
        return False, h
    floor = _floor(B64_FLOOR, len(t)) - (0.15 if sensitive_context else 0.0)
    return h >= floor, h


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

SENSITIVE_FILES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pgpass", ".netrc", ".npmrc",
    "credentials", "credentials.json", "service-account.json", ".htpasswd", "secrets.json",
}
SENSITIVE_EXTS = {".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk", ".kdbx"}
CERT_EXTS = (".pem", ".crt", ".cer", ".der")  # base64 bodies: skip entropy, keep private-key rule
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "Cargo.lock", "composer.lock", "go.sum", "Gemfile.lock", "uv.lock", IGNORE_FILE,
}
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".lock", ".map", ".min.js", ".min.css",
}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache"}


def is_env_file(path: str) -> bool:
    name = os.path.basename(path)
    return (name == ".env" or name.startswith(".env.") or name.endswith(".env")) and not name.endswith(SAFE_ENV_SUFFIXES)


def is_sensitive_file(path: str) -> str | None:
    name = os.path.basename(path)
    lower = name.lower()
    if is_env_file(path):
        return ".env file committed"
    if lower in SENSITIVE_FILES:
        return "credential file committed"
    if any(lower.endswith(ext) for ext in SENSITIVE_EXTS):
        return "key/certificate file committed"
    return None


def should_skip(path: str) -> bool:
    name = os.path.basename(path).lower()
    return name in {s.lower() for s in SKIP_FILES} or any(name.endswith(e) for e in SKIP_EXTS)


def load_ignore_globs(root: Path) -> list[str]:
    f = root / IGNORE_FILE
    if not f.is_file():
        return []
    globs = []
    for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            globs.append(line)
    return globs


def is_ignored(path: str, globs: list[str]) -> bool:
    p = path.replace("\\", "/")
    for g in globs:
        g = g.rstrip("/")
        if fnmatch.fnmatch(p, g) or fnmatch.fnmatch(os.path.basename(p), g) or p.startswith(g + "/"):
            return True
    return False


# ---------------------------------------------------------------------------
# Line scanning
# ---------------------------------------------------------------------------


MAX_ENTROPY_LINE = 2000  # longer lines are minified/generated; format rules still run on them


def scan_line(path: str, lineno: int, line: str) -> list[Finding]:
    """Scan one line. Prefer scan_text() for whole files (it computes per-file flags once)."""
    return _scan_line(path, lineno, line, is_env_file(path), path.lower().endswith(CERT_EXTS))


def _scan_line(path: str, lineno: int, line: str, env_file: bool, cert_file: bool) -> list[Finding]:
    if len(line) < 6 or IGNORE_MARKER in line:
        return []
    findings: list[Finding] = []
    claimed: list[tuple[int, int]] = []

    def overlaps(a: int, b: int) -> bool:
        return any(a < y and x < b for x, y in claimed)

    lower = line.lower()

    # Layer 1: known formats (each regex only runs if its keyword is on the line)
    for rule in RULES if ANY_KEYWORD.search(lower) else ():
        if rule.keywords and not any(k in lower for k in rule.keywords):
            continue
        for m in rule.regex.finditer(line):
            s, e = m.span(rule.group)
            if overlaps(s, e):
                continue
            if rule.name == "Credentials in URL" and _is_placeholder(m.group(rule.group)):
                continue
            claimed.append((s, e))
            name = rule.name
            if name == "JSON Web Token":
                role = jwt_role(m.group(rule.group))
                if role == "anon":
                    continue  # Supabase anon keys are meant to be public
                if role == "service_role":
                    name = "Supabase Service Role Key"
            findings.append(Finding(path, lineno, name, "pattern", m.group(rule.group)))

    # Secrets named as browser-exposed env vars (NEXT_PUBLIC_..., VITE_..., ...)
    if any(k in lower for k in PUBLIC_ENV_KEYWORDS):
        for m in PUBLIC_ENV.finditer(line):
            s, e = m.span()
            if overlaps(s, e) or not exposed_env_name(m.group()):
                continue
            claimed.append((s, e))
            findings.append(Finding(path, lineno, "Secret exposed to browser", "exposed", m.group(),
                                    "sent to every visitor's browser"))

    # Sensitive assignments
    if env_file:
        m = ENV_ASSIGN.match(line)
        if m and not line.lstrip().startswith("#"):
            key, raw = m.group(1), m.group(2)
            value = raw.split(" #")[0].strip().strip("'\"")
            vstart = line.find(value) if value else -1
            if SENSITIVE_NAME.search(key) and len(value) >= 6 and not _is_placeholder(value) and not overlaps(vstart, vstart + len(value)):
                claimed.append((vstart, vstart + len(value)))
                findings.append(Finding(path, lineno, "Secret in .env", "pattern", value, key))
    elif SENSITIVE_NAME.search(line):
        for m in CODE_ASSIGN.finditer(line):
            key, value = m.group(1), m.group(2)
            s, e = m.span(2)
            if re.match(r"^(?:[a-z][a-z0-9+.\-]*://|/|\./|\.\./)", value):
                continue  # URLs and paths (token_url = "https://...") aren't secrets
            last = re.split(r"[.\[\]>]", key)[-1] or key  # token.type -> "type", config.api_key -> "api_key"
            classes = sum(bool(re.search(c, value)) for c in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
            if value.startswith(("(?", "^", "\\")) or classes < 2 or "{" in value or "%s" in value:
                continue  # regexes, plain words, f-string/format templates
            if looks_like_identifier(value) or word_coverage(value) > 0.7:
                continue  # enum-style values: "client_secret_post", "private_key_jwt"
            if SENSITIVE_NAME.search(last) and not _is_placeholder(value) and not overlaps(s, e):
                h = calculate_entropy(value)
                if h >= 3.0:  # below this it's usually an enum/word, e.g. auth_mode = "password"
                    claimed.append((s, e))
                    findings.append(Finding(path, lineno, "Hardcoded credential", "pattern", value, f"{key} · {h:.2f} bits"))

    # Layer 2: entropy (certificate bodies are base64 by design; the private-key rule still runs)
    if cert_file or len(line) < 20 or len(line) > MAX_ENTROPY_LINE:
        return findings
    # Blank out URLs (keys inside URLs are already covered by the format rules above).
    entropy_line = URL.sub(lambda u: " " * len(u.group()), line) if ("://" in line or "www." in lower) else line
    for m in TOKEN.finditer(entropy_line):
        s, e = m.span()
        if overlaps(s, e) or (s > 0 and entropy_line[s - 1] == "\\"):
            continue  # \x41ABC... escape sequences in byte strings
        # Context is local: a sensitive word in the 40 chars before the token
        # (e.g. `api_key = "...`), not anywhere on a 5,000-char minified line.
        sensitive_ctx = bool(SENSITIVE_NAME.search(entropy_line[max(0, s - 40):s]))
        hit, h = entropy_hit(m.group(), sensitive_ctx)
        if hit:
            claimed.append((s, e))
            findings.append(Finding(path, lineno, "High-entropy string", "entropy", m.group(), f"{h:.2f} bits/char"))

    return findings


def scan_text(path: str, lines: Iterable[tuple[int, str]]) -> list[Finding]:
    env_file = is_env_file(path)
    cert_file = path.lower().endswith(CERT_EXTS)
    out: list[Finding] = []
    for lineno, line in lines:
        out.extend(_scan_line(path, lineno, line, env_file, cert_file))
    return out


# ---------------------------------------------------------------------------
# Git integration
# ---------------------------------------------------------------------------


class GitError(RuntimeError):
    pass


def git(*args: str, cwd: str | Path | None = None) -> str:
    try:
        r = subprocess.run(
            ["git", "-c", "core.quotepath=false", *args],
            cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except FileNotFoundError as e:
        raise GitError("git is not installed or not on PATH") from e
    if r.returncode != 0:
        raise GitError(r.stderr.strip() or f"git {' '.join(args)} failed")
    return r.stdout


def repo_root(cwd: str | Path | None = None) -> Path:
    return Path(git("rev-parse", "--show-toplevel", cwd=cwd).strip())


def diff_path(target: str) -> str | None:
    """Turn the path from a `+++ b/<path>` diff header into a real path.

    git appends a TAB when the path contains spaces, and C-quotes paths with
    quotes/backslashes/control characters: "b/we\\"ird\\tname".
    """
    target = target.rstrip("\t\r")
    if target == "/dev/null":
        return None
    if target.startswith('"') and target.endswith('"') and len(target) >= 2:
        raw = target[1:-1]
        try:
            target = raw.encode("latin-1", "backslashreplace").decode("unicode_escape").encode("latin-1").decode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            target = raw
    return target[2:] if target.startswith("b/") else target


HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def parse_diff(diff: str) -> dict[str, list[tuple[int, str]]]:
    """Map each file in a unified diff (-U0) to its added lines with new-file line numbers."""
    files: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    lineno = 0
    for raw in diff.splitlines():
        if raw.startswith("diff --git"):
            current = None
        elif raw.startswith("+++ "):
            current = diff_path(raw[4:])
            if current is not None:
                files.setdefault(current, [])
        elif raw.startswith("@@"):
            m = HUNK.match(raw)
            lineno = int(m.group(1)) if m else 0
        elif current is not None and raw.startswith("+"):
            files[current].append((lineno, raw[1:]))
            lineno += 1
        elif current is not None and raw.startswith(" "):
            lineno += 1
    return files


def scan_staged(cwd: str | Path | None = None) -> tuple[list[Finding], int]:
    """Scan only what is about to be committed: added lines in the index, plus sensitive filenames."""
    root = repo_root(cwd)
    globs = load_ignore_globs(root)
    names = [n for n in git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z", cwd=root).split("\0") if n]
    diff = git("diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--diff-filter=ACMR", cwd=root)
    added = parse_diff(diff)

    findings: list[Finding] = []
    scanned = 0
    for name in names:
        if is_ignored(name, globs):
            continue
        scanned += 1
        reason = is_sensitive_file(name)
        if reason:
            findings.append(Finding(name, 0, "Sensitive file", "file", os.path.basename(name), reason))
        if should_skip(name):
            continue
        findings.extend(scan_text(name, added.get(name, [])))
    return findings, scanned


COMMIT_MARK = "\x00gitghost-commit "


def scan_history(cwd: str | Path | None = None, max_count: int | None = None, all_refs: bool = False) -> tuple[list[Finding], int]:
    """Scan every line ever added in the repo's history. Streams `git log -p` so big repos don't blow up memory.

    Returns (findings, commits_scanned). Each secret is reported once, at the commit that introduced it.
    """
    root = repo_root(cwd)
    globs = load_ignore_globs(root)
    args = ["git", "-c", "core.quotepath=false", "log", "-p", "-U0", "--no-color", "--no-ext-diff",
            "--diff-filter=AMR", "--format=%x00gitghost-commit %h", "--reverse"]
    if all_refs:
        args.append("--all")
    if max_count:
        args.append(f"--max-count={max_count}")
    try:
        proc = subprocess.Popen(args, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace")
    except FileNotFoundError as e:
        raise GitError("git is not installed or not on PATH") from e

    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    commits = 0
    commit = ""
    path: str | None = None
    lineno = 0
    flags = (False, False)

    def report(fs: list[Finding]) -> None:
        for f in fs:
            key = (f.file, f.rule, f.secret)
            if key not in seen:  # --reverse => first sighting is the commit that introduced it
                seen.add(key)
                findings.append(Finding(f.file, f.line, f.rule, f.kind, f.secret, f.detail, commit))

    assert proc.stdout is not None
    for raw in proc.stdout:
        raw = raw.rstrip("\n")
        if raw.startswith(COMMIT_MARK):
            commit, path, commits = raw[len(COMMIT_MARK):].strip(), None, commits + 1
        elif raw.startswith("diff --git"):
            path = None
        elif raw.startswith("+++ "):
            path = diff_path(raw[4:])
            if path is not None and (is_ignored(path, globs) or should_skip(path)):
                reason = is_sensitive_file(path) if not is_ignored(path, globs) else None
                if reason:
                    report([Finding(path, 0, "Sensitive file", "file", os.path.basename(path), reason)])
                path = None
            elif path is not None:
                flags = (is_env_file(path), path.lower().endswith(CERT_EXTS))
                reason = is_sensitive_file(path)
                if reason:
                    report([Finding(path, 0, "Sensitive file", "file", os.path.basename(path), reason)])
        elif raw.startswith("@@"):
            m = HUNK.match(raw)
            lineno = int(m.group(1)) if m else 0
        elif path is not None and raw.startswith("+"):
            report(_scan_line(path, lineno, raw[1:], *flags))
            lineno += 1
    proc.wait()
    if proc.returncode not in (0, None):
        err = proc.stderr.read() if proc.stderr else ""
        if "does not have any commits" in err:
            return [], 0
        raise GitError(err.strip() or "git log failed")
    return findings, commits


def iter_files(target: Path) -> Iterator[Path]:
    """Files to scan under target. Inside a git repo this is exactly what git sees:
    tracked + untracked files, minus anything in .gitignore (venv/, build output, caches)."""
    if target.is_file():
        yield target
        return
    try:
        out = git("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", ".", cwd=target)
    except GitError:
        out = None  # not a git repo (or git missing): walk the folder instead
    if out is not None:
        for rel in dict.fromkeys(n for n in out.split("\0") if n):  # dedupe, keep order
            f = target / rel
            if f.is_file():
                yield f
        return
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            yield Path(dirpath) / f


def read_text_file(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None  # binary
    return data.decode("utf-8", errors="replace")


def scan_path(target: str | Path) -> tuple[list[Finding], int]:
    """Scan every text file under a directory (or a single file), all lines."""
    target = Path(target).resolve()
    base = target if target.is_dir() else target.parent
    globs = load_ignore_globs(base)
    findings: list[Finding] = []
    scanned = 0
    for f in iter_files(target):
        rel = f.relative_to(base).as_posix()
        if is_ignored(rel, globs):
            continue
        reason = is_sensitive_file(rel)
        if reason:
            findings.append(Finding(rel, 0, "Sensitive file", "file", f.name, reason))
        if should_skip(rel):
            continue
        text = read_text_file(f)
        if text is None:
            continue
        scanned += 1
        findings.extend(scan_text(rel, enumerate(text.splitlines(), start=1)))
    return findings, scanned

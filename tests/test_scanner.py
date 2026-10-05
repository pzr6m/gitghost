"""Tests for GitGhost.

Fake keys are assembled at runtime (e.g. "sk_" + "live_") so this file itself never
contains a key-shaped string — otherwise GitHub push protection would block the repo.
"""

import os
import random
import string
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gitghost.cli import app
from gitghost.scanner import (
    calculate_entropy,
    entropy_hit,
    is_sensitive_file,
    mask,
    parse_diff,
    scan_line,
    scan_path,
)

runner = CliRunner()
rng = random.Random(42)
B64 = string.ascii_letters + string.digits


def rand(n, alphabet=B64):
    return "".join(rng.choice(alphabet) for _ in range(n))


def rules(line, path="app.py"):
    return [f.rule for f in scan_line(path, 1, line)]


# --- entropy ---------------------------------------------------------------


def test_entropy_values():
    assert calculate_entropy("") == 0
    assert calculate_entropy("aaaa") == 0
    assert calculate_entropy("ab") == pytest.approx(1.0)
    assert calculate_entropy("0123456789abcdef") == pytest.approx(4.0)


def test_entropy_flags_random_tokens_of_all_lengths():
    # The naive "> 4.5" rule misses all of these under ~32 chars.
    for n in (20, 24, 32, 40, 64):
        misses = sum(not entropy_hit(rand(n), False)[0] for _ in range(200))
        assert misses / 200 < 0.15, f"length {n}: missed {misses}/200"


@pytest.mark.parametrize("token", [
    "getUserAccountSettings2", "MyComponentPropsWithRef1", "test_user_password_reset_token_v2",
    "aaaaaaaaaaaaaaaaaaaaaaaaa1", "src/components/forms/LoginForm", "handleAuthenticationCallback",
])
def test_entropy_ignores_identifiers(token):
    assert not entropy_hit(token, False)[0]


def test_hex_only_flagged_with_sensitive_context():
    h = rand(40, "0123456789abcdef")
    assert not rules(f'commit = "{h}"')  # git SHAs are everywhere
    assert "High-entropy string" in rules(f'SECRET_KEY = "{h}"') or "Hardcoded credential" in rules(f'SECRET_KEY = "{h}"')


# --- known formats ---------------------------------------------------------


@pytest.mark.parametrize("secret,rule", [
    ("AKIA" + "IOSFODNN7" + "EXAMPLE", "AWS Access Key ID"),
    ("sk-" + "proj-" + rand(40), "OpenAI API Key"),
    ("sk-" + rand(48), "OpenAI API Key"),
    ("sk-" + "ant-" + "api03-" + rand(90), "Anthropic API Key"),
    ("sk_" + "live_" + rand(24), "Stripe Live Key"),
    ("gh" + "p_" + rand(36), "GitHub Token"),
    ("github_" + "pat_" + rand(82), "GitHub Fine-grained PAT"),
    ("AI" + "za" + rand(35), "Google API Key"),
    ("xo" + "xb-" + "1234567890-" + rand(24), "Slack Token"),
    ("hf" + "_" + rand(34), "Hugging Face Token"),
    ("-----BEGIN RSA " + "PRIVATE KEY-----", "Private Key Block"),
    ("eyJ" + rand(20) + ".eyJ" + rand(30) + "." + rand(43), "JSON Web Token"),
])
def test_known_formats(secret, rule):
    found = rules(f'x = "{secret}"')
    assert rule in found, found


def test_blueprint_test_key_is_caught():
    assert "OpenAI API Key" in rules('OPENAI_KEY = "sk-' + 'proj-1234567890abcdef1234567890abcdef"')


def test_anthropic_not_double_reported_as_openai():
    found = rules('k = "sk-' + "ant-" + rand(60) + '"')
    assert found == ["Anthropic API Key"]


def test_db_url_with_password():
    assert "Credentials in URL" in rules('DATABASE_URL = "postgres://admin:' + 'Tr0ub4dor3x@db.example.com:5432/app"')


def test_one_finding_per_secret():
    assert len(scan_line("a.py", 1, 'STRIPE = "sk_' + "live_" + rand(30) + '"')) == 1


# --- assignments / false positives ----------------------------------------


def test_hardcoded_password_in_code():
    assert "Hardcoded credential" in rules('db_password = "Xk9#mP2vQ8!z"')


@pytest.mark.parametrize("line", [
    'password = os.environ["DB_PASSWORD"]',
    'token = get_token()',
    'API_KEY = "your_api_key_here"',
    'password = "changeme"',
    'secret = "${SECRET}"',
    'auth_mode = "password"',
    'token_url = "https://oauth2.googleapis.com/token"',
    'api_key = "xxxxxxxxxxxxxxxx"',
    'import { useAuthenticationContext } from "./hooks/useAuthenticationContext"',
])
def test_false_positives(line):
    assert scan_line("app.py", 1, line) == []


def test_env_file_lines():
    assert rules("OPENAI_API_KEY=abc123def456ghi", ".env") == ["Secret in .env"]
    assert rules("DEBUG=true", ".env") == []
    assert rules("DB_PASSWORD=", ".env") == []
    assert rules("# DB_PASSWORD=hunter2hunter", ".env") == []


def test_pem_private_key_caught_but_public_cert_bodies_ignored():
    assert rules("-----BEGIN " + "PRIVATE KEY-----", "server.pem") == ["Private Key Block"]
    assert rules(rand(64), "ca.pem") == []


@pytest.mark.parametrize("token", [
    "CAP_OPENNI_QVGA_30HZ", "XML_CHAR_ENCODING_UTF16LE", "PyUnicode_GetSize", "SOCKS5ProxyRequest",
])
def test_identifiers_with_digits_not_flagged(token):
    assert rules(f"x = {token}  # 1") == []


def test_inline_ignore():
    assert rules('k = "sk_' + "live_" + rand(24) + '"  # gitghost:ignore') == []


# --- files -----------------------------------------------------------------


@pytest.mark.parametrize("path,hit", [
    (".env", True), ("config/.env.production", True), (".env.example", False), (".env.sample", False),
    ("id_rsa", True), ("certs/server.key", True), ("certs/ca-bundle.pem", False), ("main.py", False), ("README.md", False),
])
def test_sensitive_files(path, hit):
    assert bool(is_sensitive_file(path)) is hit


def test_mask_never_leaks_full_secret():
    s = "sk_" + "live_" + rand(30)
    m = mask(s)
    assert s not in m and m.startswith(s[:6]) and m.endswith(s[-4:])
    assert mask("short") == "*****"


# --- diff parsing ----------------------------------------------------------


def test_parse_diff_line_numbers():
    diff = """diff --git a/app.py b/app.py
index 1..2 100644
--- a/app.py
+++ b/app.py
@@ -3,0 +4,2 @@ def x():
+line four
+line five
@@ -10 +12 @@
+line twelve
diff --git a/gone.py b/gone.py
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-bye
"""
    out = parse_diff(diff)
    assert out == {"app.py": [(4, "line four"), (5, "line five"), (12, "line twelve")]}


# --- path scanning ---------------------------------------------------------


def test_scan_path_and_ignore_file(tmp_path):
    (tmp_path / "app.py").write_text('KEY = "sk_' + "live_" + rand(24) + '"\n')
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "fake.py").write_text('KEY = "sk_' + "live_" + rand(24) + '"\n')
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text('k="sk_' + "live_" + rand(24) + '"')
    (tmp_path / ".gitghostignore").write_text("# test data\nfixtures/\n")
    findings, scanned = scan_path(tmp_path)
    assert [(f.file, f.line) for f in findings] == [("app.py", 1)]


# --- end to end: real git repo + real hook --------------------------------


def sh(*args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path):
    sh("git", "init", "-q", cwd=tmp_path)
    sh("git", "config", "user.email", "t@t.t", cwd=tmp_path)
    sh("git", "config", "user.name", "t", cwd=tmp_path)
    sh("git", "config", "commit.gpgsign", "false", cwd=tmp_path)
    old = os.getcwd()
    os.chdir(tmp_path)
    yield tmp_path
    os.chdir(old)


def test_hook_blocks_secret_commit(repo):
    assert runner.invoke(app, ["install"]).exit_code == 0
    (repo / "leak.py").write_text('OPENAI_KEY = "sk-' + 'proj-1234567890abcdef1234567890abcdef"\n')
    sh("git", "add", "leak.py", cwd=repo)
    r = sh("git", "commit", "-m", "leak", cwd=repo)
    assert r.returncode != 0
    assert "COMMIT BLOCKED" in r.stdout + r.stderr
    assert "1234567890abcdef1234567890abcdef" not in r.stdout  # masked
    assert sh("git", "rev-parse", "HEAD", cwd=repo).returncode != 0  # nothing committed


def test_hook_allows_clean_commit(repo):
    runner.invoke(app, ["install"])
    (repo / "ok.py").write_text("print('hello')\n")
    sh("git", "add", "ok.py", cwd=repo)
    r = sh("git", "commit", "-m", "ok", cwd=repo)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "clean" in r.stdout + r.stderr  # git sends hook output to stderr


def test_hook_blocks_env_file(repo):
    runner.invoke(app, ["install"])
    (repo / ".env").write_text("DEBUG=true\n")
    sh("git", "add", ".env", cwd=repo)
    assert sh("git", "commit", "-m", "env", cwd=repo).returncode != 0


def test_only_new_lines_are_scanned(repo):
    (repo / "a.py").write_text('k = "sk_' + "live_" + rand(24) + '"  # gitghost:ignore\n')
    sh("git", "add", ".", cwd=repo)
    sh("git", "commit", "-qm", "init", cwd=repo)
    (repo / "a.py").write_text((repo / "a.py").read_text() + "print(1)\n")
    sh("git", "add", ".", cwd=repo)
    r = runner.invoke(app, ["scan", "--hook"])
    assert r.exit_code == 0, r.output


def test_install_preserves_existing_hook_and_uninstall_restores(repo):
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho custom-check\nexit 0\n")
    runner.invoke(app, ["install"])
    text = hook.read_text()
    assert "echo custom-check" in text
    assert text.index("gitghost") < text.index("exit 0")  # runs before the existing exit
    runner.invoke(app, ["install"])  # idempotent
    assert hook.read_text().count(">>> gitghost >>>") == 1
    runner.invoke(app, ["uninstall"])
    assert hook.read_text() == "#!/bin/sh\necho custom-check\nexit 0\n"


def test_uninstall_removes_hook_file(repo):
    runner.invoke(app, ["install"])
    runner.invoke(app, ["uninstall"])
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


def test_json_output_and_exit_codes(repo):
    (repo / "x.py").write_text('k = "gh' + 'p_' + rand(36) + '"\n')
    r = runner.invoke(app, ["scan", str(repo), "--json"])
    assert r.exit_code == 1 and '"GitHub Token"' in r.output
    r = runner.invoke(app, ["scan", "--json"])  # nothing staged
    assert r.exit_code == 0


def test_not_a_git_repo(tmp_path):
    old = os.getcwd()
    os.chdir(tmp_path)
    try:
        assert runner.invoke(app, ["scan"]).exit_code == 2
    finally:
        os.chdir(old)

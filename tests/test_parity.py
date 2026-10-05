"""The web grader (docs/scanner.js) must find exactly what the Python scanner finds.

Generates a few thousand lines mixing real key shapes, random tokens, identifiers,
placeholders, URLs and .env lines, runs both scanners on them, and compares.
"""

import json
import random
import shutil
import string
import subprocess
from pathlib import Path

import pytest

from gitghost.scanner import scan_text

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed")

rng = random.Random(7)
B64 = string.ascii_letters + string.digits
B64X = B64 + "+/_-"
HEX = "0123456789abcdef"


def r(n, a=B64):
    return "".join(rng.choice(a) for _ in range(n))


def corpus():
    keys = [
        lambda: "AKIA" + r(16, string.ascii_uppercase + string.digits),
        lambda: "sk-" + "proj-" + r(rng.randint(20, 60), B64 + "_-"),
        lambda: "sk-" + r(48),
        lambda: "sk-" + "ant-" + r(90, B64 + "_-"),
        lambda: "sk_" + "live_" + r(rng.randint(20, 40)),
        lambda: "gh" + rng.choice("pousr") + "_" + r(36),
        lambda: "AI" + "za" + r(35, B64 + "_-"),
        lambda: "xo" + "xb-" + r(30, B64 + "-"),
        lambda: "hf" + "_" + r(34),
        lambda: "eyJ" + r(20) + ".eyJ" + r(30) + "." + r(43),
        lambda: r(rng.randint(16, 70), B64X),
        lambda: r(rng.choice([32, 40, 64]), HEX),
        lambda: rng.choice(["getUserAccountSettings2", "CAP_OPENNI_QVGA_30HZ", "PyUnicode_GetSize",
                            "your_api_key_here", "changeme", "${SECRET}", "xxxxxxxxxxxxxxxx",
                            "client_secret_post", "aaaaaaaaaaaaaaaaaaaaaaaaa1", "SOCKS5ProxyRequest"]),
    ]
    names = ["api_key", "API_KEY", "token", "secret", "db_password", "auth", "author", "config.api_key",
             "token.type", "name", "x", "SESSION_SALT", "client_secret", "pwd", "headers['Authorization']"]
    templates = [
        '{n} = "{v}"', "{n}: '{v}'", '"{n}": "{v}",', "const {n} = `{v}`;", "{n} := \"{v}\"",
        "print('{v}')", "# {v}", "url = 'https://user:{v}@db.example.com/x'", "see https://example.com/{v}",
        "x = b'\\x41{v}'", "{n} = os.environ['{v}']", "{v}", '{n} = "{v}"  # gitghost:ignore',
        "-----BEGIN RSA " + "PRIVATE KEY-----", "{n}=\"{v}\" {n}=\"{v}\"",
    ]
    files = []
    for fi in range(40):
        path = rng.choice(["app.py", "src/config.js", ".env", ".env.production", "settings.yaml", "certs/a.pem", ".env.example"])
        lines = []
        for _ in range(100):
            v = rng.choice(keys)()
            lines.append(rng.choice(templates).format(n=rng.choice(names), v=v))
            if path.startswith(".env") and rng.random() < 0.5:
                lines[-1] = f"{rng.choice(names).upper().replace('.', '_')}={v}"
        files.append({"path": f"f{fi}/{path}", "text": "\n".join(lines) + "\n"})
    # plus this project's own source code (realistic non-secret code)
    for p in sorted((ROOT / "gitghost").glob("*.py")) + [ROOT / "README.md"]:
        files.append({"path": p.name, "text": p.read_text(encoding="utf-8")})
    return files


def test_js_scanner_matches_python():
    files = corpus()
    py = []
    for f in files:
        lines = enumerate(f["text"].splitlines(), start=1)
        py += [[x.file, x.line, x.rule, x.kind, x.secret] for x in scan_text(f["path"], lines)]
    res = subprocess.run([NODE, str(ROOT / "tests" / "parity.js")], input=json.dumps(files),
                         capture_output=True, text=True, encoding="utf-8", check=True)
    js = json.loads(res.stdout)
    assert len(py) > 500, "corpus should produce plenty of findings"
    only_py = [x for x in py if x not in js]
    only_js = [x for x in js if x not in py]
    assert not only_py and not only_js, f"only in Python: {only_py[:5]}\nonly in JS: {only_js[:5]}"

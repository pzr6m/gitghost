"""Regenerate docs/demo.svg (README screenshot) from a throwaway repo with fake keys."""
import os, subprocess, tempfile
from rich.console import Console
from rich.terminal_theme import MONOKAI
import gitghost.cli as cli

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo.svg")
with tempfile.TemporaryDirectory() as d:
    os.chdir(d)
    subprocess.run(["git", "init", "-q"], check=True)
    k1 = "sk-" + "proj-" + "Xa91kQ2vB7mN4pL8zR3tY6wE0uI5oH2gF7dS1aZ"
    k2 = "sk_" + "live_" + "51HxQ2Lk9vB7mN4pR3tY6wE0"
    open("config.py", "w").write(
        f'import os\n\nOPENAI_KEY = "{k1}"\nSTRIPE_KEY = "{k2}"\n'
        'DB_URL = "postgres://admin:Tr0ub4dor3x@db.prod.internal:5432/app"\n'
        'session_salt = "q8Zt3LmV0xKp7Rw2NcYb5HfJ"\n'
    )
    open(".env", "w").write("DEBUG=true\nJWT_SECRET=9fK2mQ7xL4pZ8vR1\n")
    subprocess.run(["git", "add", "-A"], check=True)
    cli.console = Console(record=True, width=118, force_terminal=True, color_system="truecolor", highlight=False)
    try:
        cli.scan(path=None, hook=True, as_json=False)
    except BaseException:
        pass
    cli.console.save_svg(out, title='git commit -m "add config"', theme=MONOKAI)
print("wrote", out)

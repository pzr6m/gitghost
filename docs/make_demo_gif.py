"""Render docs/demo.gif: a terminal recording built from GitGhost's real output.

Needs: pip install playwright pillow && playwright install chromium
"""
import html
import io
import os
import subprocess
import sys
import tempfile

from PIL import Image
from playwright.sync_api import sync_playwright
from rich.console import Console
from rich.terminal_theme import MONOKAI

import gitghost.cli as cli

COLS, ROWS = 96, 33
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo.gif")
KEY = "sk-" + "proj-" + "Xa91kQ2vB7mN4pL8zR3tY6wE0uI5oH2gF7dS1aZ"


def capture(fn) -> list[str]:
    """Run a GitGhost function and return its output as a list of HTML lines."""
    cli.console = Console(record=True, width=COLS, force_terminal=True, color_system="truecolor", highlight=False)
    try:
        fn()
    except BaseException:
        pass
    code = cli.console.export_html(inline_styles=True, code_format="{code}", theme=MONOKAI)
    return code.rstrip("\n").split("\n")


def run(*a):
    subprocess.run(a, check=True, capture_output=True)


with tempfile.TemporaryDirectory() as d:
    os.chdir(d)
    run("git", "init", "-q", "-b", "main")
    run("git", "config", "user.email", "demo@example.com")
    run("git", "config", "user.name", "demo")
    open("config.py", "w").write(f'OPENAI_KEY = "{KEY}"\n')
    run("git", "add", "config.py")
    blocked = capture(lambda: cli.scan(path=None, history=False, all_refs=False, hook=True, as_json=False))
    open("config.py", "w").write('import os\nOPENAI_KEY = os.environ["OPENAI_KEY"]\n')
    run("git", "add", "config.py")
    clean = capture(lambda: cli.scan(path=None, history=False, all_refs=False, hook=True, as_json=False))

esc = html.escape
PROMPT = '<span style="color:#a6e3a1;font-weight:bold">~/my-app</span> <span style="color:#cba6f7">❯</span> '
frames: list[tuple[list[str], int]] = []  # (lines, duration ms)
buf: list[str] = []


def snap(ms):
    frames.append((list(buf), ms))


def type_cmd(cmd, after=350):
    buf.append(PROMPT)
    for i in range(0, len(cmd) + 1, 2):
        buf[-1] = PROMPT + esc(cmd[:i]) + '<span style="background:#cdd6f4">&nbsp;</span>'
        snap(45)
    buf[-1] = PROMPT + esc(cmd)
    snap(after)


def out(lines, ms):
    buf.extend(lines)
    snap(ms)


type_cmd("gitghost install")
out(['<span style="color:#a6e3a1;font-weight:bold">👻 Installed pre-commit hook</span> <span style="color:#6c7086">→ .git/hooks/pre-commit</span>'], 900)
type_cmd(f"echo 'OPENAI_KEY = \"{KEY[:24]}…\"' > config.py")
type_cmd('git add config.py && git commit -m "add config"', 500)
out(blocked, 4200)
type_cmd("echo 'OPENAI_KEY = os.environ[\"OPENAI_KEY\"]' > config.py", 300)
type_cmd('git add config.py && git commit -m "add config"', 450)
out(clean + ['[main 3f2a1c9] add config', ' 1 file changed, 2 insertions(+)'], 600)
buf.append(PROMPT + '<span style="background:#cdd6f4">&nbsp;</span>')
snap(3200)

PAGE = """<html><head><style>
body{margin:0;background:transparent}
.win{background:#1e1e2e;border-radius:12px;width:%dpx;box-shadow:0 18px 50px rgba(0,0,0,.45);overflow:hidden;font-family:'DejaVu Sans Mono','Noto Color Emoji',monospace}
.bar{height:34px;background:#181825;display:flex;align-items:center;padding-left:14px;gap:8px;position:relative}
.dot{width:12px;height:12px;border-radius:50%%}
.title{position:absolute;left:0;right:0;text-align:center;color:#7f849c;font:13px sans-serif}
pre{margin:0;padding:14px 18px 18px;color:#cdd6f4;font-size:13.5px;line-height:17px;height:%dpx;white-space:pre;overflow:hidden;font-family:inherit}
</style></head><body><div class="win" id="w"><div class="bar"><div class="dot" style="background:#f38ba8"></div><div class="dot" style="background:#f9e2af"></div><div class="dot" style="background:#a6e3a1"></div><div class="title">gitghost — zsh</div></div><pre id="t"></pre></div></body></html>"""
width_px = int(COLS * 8.15) + 36

images, durations = [], []
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": width_px + 40, "height": ROWS * 17 + 100}, device_scale_factor=1)
    pg.set_content(PAGE % (width_px, ROWS * 17))
    win = pg.locator("#w")
    last = None
    for lines, ms in frames:
        content = "\n".join(lines[-ROWS:])
        if content == last and durations:
            durations[-1] += ms
            continue
        last = content
        pg.evaluate("c => document.getElementById('t').innerHTML = c", content)
        png = win.screenshot(omit_background=True)
        images.append(Image.open(io.BytesIO(png)).convert("RGB"))
        durations.append(ms)
    b.close()

# Build one palette from every distinct frame, so colours that only appear late (the red alert) survive.
sheet = Image.new("RGB", (images[0].width, images[0].height * len(images[::4])))
for i, im in enumerate(images[::4]):
    sheet.paste(im, (0, i * im.height))
pal = sheet.quantize(colors=160, method=Image.Quantize.MEDIANCUT)
q = [im.quantize(palette=pal, dither=Image.Dither.NONE) for im in images]
q[0].save(OUT, save_all=True, append_images=q[1:], duration=durations, loop=0, optimize=True, disposal=1)
print(f"wrote {OUT}: {len(q)} frames, {sum(durations)/1000:.1f}s, {os.path.getsize(OUT)/1024:.0f} KB")

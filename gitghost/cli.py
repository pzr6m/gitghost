"""GitGhost CLI: scan, install, uninstall."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .scanner import Finding, GitError, git, repo_root, scan_history, scan_path, scan_staged

# Windows: when git runs the hook, output is a pipe in the legacy code page (cp1252), and
# printing 👻 or box-drawing characters would crash Python and block every commit.
for _stream in (sys.stdout, sys.stderr):
    try:
        if _stream is not None and (_stream.encoding or "").lower().replace("-", "") != "utf8":
            _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:  # pragma: no cover - exotic streams
        pass

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="👻 [bold]GitGhost[/] stops you from committing passwords and API keys to git.\n\nStart with: [cyan]gitghost install[/] (inside your project folder)",
)
console = Console(highlight=False)
err = Console(stderr=True, highlight=False)

LOGO = r"""
   ██████╗ ██╗████████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ██╔════╝ ██║╚══██╔══╝██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
  ██║  ███╗██║   ██║   ██║  ███╗███████║██║   ██║███████╗   ██║
  ██║   ██║██║   ██║   ██║   ██║██╔══██║██║   ██║╚════██║   ██║
  ╚██████╔╝██║   ██║   ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
   ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝"""

HOOK_START = "# >>> gitghost >>>"
HOOK_END = "# <<< gitghost <<<"


def print_logo() -> None:
    console.print(Text(LOGO, style="bold bright_magenta"))
    console.print(f"  [dim]secret scanner · v{__version__}[/]\n")


def version_cb(value: bool) -> None:
    if value:
        console.print(f"gitghost {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(None, "--version", "-V", callback=version_cb, is_eager=True, help="Show version."),
) -> None:
    pass


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def render_findings(findings: list[Finding], scanned: int, staged: bool, history: bool = False) -> None:
    table = Table(box=box.HEAVY_HEAD, border_style="red", header_style="bold white on red", expand=True, show_lines=False)
    if history:
        table.add_column("Commit", style="bold yellow", no_wrap=True)
    table.add_column("File", style="bold cyan", overflow="fold", ratio=3)
    table.add_column("Line", justify="right", style="yellow", no_wrap=True)
    table.add_column("Detection", style="bold", ratio=2)
    table.add_column("Reason", style="magenta", ratio=2)
    table.add_column("Secret (masked)", style="bold red", overflow="fold", ratio=2)

    for f in findings if history else sorted(findings, key=lambda x: (x.file, x.line)):
        reason = {"pattern": "Regex match", "entropy": "High entropy", "file": "Filename", "exposed": "Public variable"}.get(f.kind, f.kind)
        if f.detail:
            reason += f"\n[dim]{f.detail}[/]"
        row = [f.file, str(f.line) if f.line else "—", f.rule, reason, "—" if f.kind == "file" else f.masked]
        table.add_row(*([f.commit] if history else []), *row)

    files_hit = len({f.file for f in findings})
    headline = Text.assemble(
        ("  🚫 COMMIT BLOCKED  " if staged else "  🚨 SECRETS FOUND  ", "bold white on red"),
        (f"  {len(findings)} potential secret{'s' * (len(findings) != 1)} in {files_hit} file{'s' * (files_hit != 1)}", "bold red"),
        (f"  ({scanned} {'commit' if history else 'file'}{'s' * (scanned != 1)} scanned)", "dim"),
    )
    if history:
        headline = Text.assemble(
            ("  🕰  SECRETS IN HISTORY  ", "bold white on red"),
            (f"  {len(findings)} potential secret{'s' * (len(findings) != 1)} in {files_hit} file{'s' * (files_hit != 1)}", "bold red"),
            (f"  ({scanned} commit{'s' * (scanned != 1)} scanned)", "dim"),
        )

    fix = Text()
    if history:
        fix.append("These are already in your git history, so editing the files now won't remove them.\n", style="bold")
        fix.append(" 1. ", style="bold yellow")
        fix.append("Rotate every real key listed above first. If the repo was ever pushed, assume they're compromised.\n")
        fix.append(" 2. ", style="bold yellow")
        fix.append("Then, if you need them gone from history: ")
        fix.append("git filter-repo --replace-text <file>", style="bold cyan")
        fix.append(" (or BFG), and force-push.\n")
        fix.append(" 3. ", style="bold yellow")
        fix.append("Run ")
        fix.append("gitghost install", style="bold cyan")
        fix.append(" so it can't happen again.")
        console.print(Panel(Group(headline, Text(""), table, Text(""), fix), border_style="bold red", box=box.DOUBLE, padding=(1, 2)))
        return
    fix.append("How to fix\n", style="bold")
    fix.append(" 1. ", style="bold yellow")
    fix.append("Move the secret into an environment variable or secrets manager, and load it at runtime.\n")
    fix.append(" 2. ", style="bold yellow")
    fix.append("Add .env / key files to .gitignore, then ")
    fix.append("git rm --cached <file>", style="bold cyan")
    fix.append("\n 3. ", style="bold yellow")
    fix.append("If this key was ever pushed anywhere, rotate it now — deleting it from git doesn't un-leak it.\n")
    fix.append(" 4. ", style="bold yellow")
    fix.append("False positive? Add ")
    fix.append("# gitghost:ignore", style="bold cyan")
    fix.append(" to the line, or a path glob to ")
    fix.append(".gitghostignore", style="bold cyan")
    if any(f.kind == "exposed" for f in findings):
        fix.append("\n\nAbout public variables: ", style="bold")
        fix.append("anything named NEXT_PUBLIC_*, VITE_*, REACT_APP_* (and similar) is copied into the JavaScript "
                   "every visitor downloads. Rename secret ones without the prefix and only use them in server code "
                   "(an API route or edge function).")
    if staged:
        fix.append("\n\nEmergency bypass (not recommended): ", style="dim")
        fix.append("git commit --no-verify", style="dim cyan")

    console.print(Panel(Group(headline, Text(""), table, Text(""), fix), border_style="bold red", box=box.DOUBLE, padding=(1, 2)))


@app.command()
def scan(
    path: Optional[Path] = typer.Argument(None, help="Folder or file to check, e.g. [cyan].[/] for the whole project. Leave out to check what you're about to commit."),
    history: bool = typer.Option(False, "--history", help="Check all your old commits for secrets that were already committed."),
    all_refs: bool = typer.Option(False, "--all", help="With --history: include every branch, not just this one."),
    hook: bool = typer.Option(False, "--hook", help="Used by the git hook: prints one short line when everything is clean.", hidden=True),
    as_json: bool = typer.Option(False, "--json", help="Output JSON (for scripts and CI)."),
) -> None:
    """Check for secrets: in what you're about to commit (default), in a folder, or in old commits."""
    if history and path is not None:
        err.print("[bold red]gitghost:[/] use either a path or --history, not both")
        raise typer.Exit(2)
    staged = path is None and not history
    if path is not None and not path.exists():
        err.print(f"[bold red]gitghost:[/] {path} does not exist")
        raise typer.Exit(2)
    try:
        if history:
            findings, scanned = scan_history(all_refs=all_refs)
        elif staged:
            findings, scanned = scan_staged()
        else:
            findings, scanned = scan_path(path)
    except GitError as e:
        err.print(f"[bold red]gitghost:[/] {e}")
        raise typer.Exit(2)
    except Exception as e:  # a bug in GitGhost must never lock someone out of committing
        err.print(f"[bold yellow]gitghost: internal error, scan skipped:[/] {type(e).__name__}: {e}")
        err.print("[dim]Please report this at the project's GitHub issues page.[/]")
        if hook and os.environ.get("GITGHOST_STRICT") != "1":
            raise typer.Exit(0)
        raise typer.Exit(2)

    if as_json:
        print(json.dumps(
            {"scanned": scanned, "unit": "commits" if history else "files", "findings": [
                {"file": f.file, "line": f.line, "rule": f.rule, "kind": f.kind, "masked": f.masked, "detail": f.detail,
                 **({"commit": f.commit} if history else {})}
                for f in findings
            ]}, indent=2, ensure_ascii=False,
        ))
        raise typer.Exit(1 if findings else 0)

    if findings:
        print_logo()
        render_findings(findings, scanned, staged, history)
        raise typer.Exit(1)

    if hook:
        console.print(f"[bold green]👻 gitghost[/] [green]✓[/] [dim]{scanned} staged file{'s' * (scanned != 1)} clean[/]")
    else:
        print_logo()
        if staged and scanned == 0:
            console.print("[yellow]Nothing staged.[/] [dim]Stage files with git add, scan a folder with [/][cyan]gitghost scan .[/][dim], or your history with [/][cyan]gitghost scan --history[/]")
        else:
            what = "commit" if history else ("staged file" if staged else "file")
            console.print(Panel(f"[bold green]✓ No secrets found[/] [dim]in {scanned} {what}{'s' * (scanned != 1)}[/]", border_style="green", box=box.ROUNDED))
    raise typer.Exit(0)


# ---------------------------------------------------------------------------
# install / uninstall
# ---------------------------------------------------------------------------


def write_hook(path: Path, content: str) -> None:
    # LF line endings even on Windows (sh chokes on CRLF); open() form works on Python 3.9.
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def hooks_dir() -> Path:
    root = repo_root()
    # Respects core.hooksPath (husky etc.) and worktrees.
    p = Path(git("rev-parse", "--git-path", "hooks", cwd=root).strip())
    return p if p.is_absolute() else (root / p)


def hook_block() -> str:
    py = Path(sys.executable).as_posix()
    return f"""{HOOK_START}
# Scans staged changes for secrets. Remove with: gitghost uninstall
GITGHOST_PY="{py}"
if [ -x "$GITGHOST_PY" ]; then
  "$GITGHOST_PY" -m gitghost scan --hook || exit 1
elif command -v gitghost >/dev/null 2>&1; then
  gitghost scan --hook || exit 1
else
  echo "gitghost: not installed, skipping secret scan" >&2
fi
{HOOK_END}
"""


def strip_block(content: str) -> str:
    if HOOK_START not in content:
        return content
    before, rest = content.split(HOOK_START, 1)
    after = rest.split(HOOK_END, 1)[1] if HOOK_END in rest else ""
    return before + after.lstrip("\n")


@app.command()
def install() -> None:
    """Turn on automatic checking: every git commit in this project gets checked."""
    try:
        hdir = hooks_dir()
    except GitError as e:
        err.print(f"[bold red]gitghost:[/] {e}")
        raise typer.Exit(2)
    hdir.mkdir(parents=True, exist_ok=True)
    hook = hdir / "pre-commit"
    existing = hook.read_text(encoding="utf-8") if hook.exists() else ""
    updating = HOOK_START in existing
    base = strip_block(existing)

    if not base.strip():
        content = "#!/bin/sh\n" + hook_block()
    elif base.startswith("#!"):
        # Insert right after the shebang so an existing `exit 0` can't skip us.
        shebang, _, body = base.partition("\n")
        content = f"{shebang}\n{hook_block()}{body}"
    else:
        content = "#!/bin/sh\n" + hook_block() + base

    write_hook(hook, content)
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    verb = "Updated" if updating else ("Added to existing" if existing.strip() else "Installed")
    console.print(f"[bold green]👻 {verb} pre-commit hook[/] [dim]→ {hook}[/]")
    console.print("[dim]Every [/][cyan]git commit[/][dim] is now scanned. Remove with [/][cyan]gitghost uninstall[/]")


@app.command()
def uninstall() -> None:
    """Turn off automatic checking for this project."""
    try:
        hook = hooks_dir() / "pre-commit"
    except GitError as e:
        err.print(f"[bold red]gitghost:[/] {e}")
        raise typer.Exit(2)
    if not hook.exists() or HOOK_START not in hook.read_text(encoding="utf-8"):
        console.print("[yellow]GitGhost isn't installed in this repo.[/]")
        raise typer.Exit(0)
    remaining = strip_block(hook.read_text(encoding="utf-8"))
    if remaining.strip() in ("", "#!/bin/sh", "#!/usr/bin/env sh", "#!/bin/bash"):
        hook.unlink()
        console.print("[bold green]Removed pre-commit hook.[/]")
    else:
        write_hook(hook, remaining)
        console.print("[bold green]Removed GitGhost[/] [dim](your other pre-commit code was kept)[/]")


if __name__ == "__main__":  # pragma: no cover
    app()

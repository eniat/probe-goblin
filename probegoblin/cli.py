"""probegoblin command line."""

from __future__ import annotations

import asyncio
import os
import re
import signal
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from probegoblin import TAGLINE, __version__
from probegoblin.core import browser
from probegoblin.core.config import Settings, load_settings
from probegoblin.core.discovery import estimate_requests
from probegoblin.core.engine import Engine
from probegoblin.core.external import INSTALL_HINTS, find_tool, tool_version
from probegoblin.core.preflight import plan_target, read_targets_file, validate_ip
from probegoblin.core.registry import Goblin, discover
from probegoblin.output.terminal import Renderer

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help=f"ProbeGoblin {__version__}: {TAGLINE.lower()}.",
)
err = Console(stderr=True)


def _module_epilog() -> str:
    try:
        goblins = discover()
    except Exception:  # help text must render even if a module is broken
        return ""
    flags = "  ".join(f"--{g.flag}" for g in goblins)
    return f"Module flags (run only these): {flags}"


def _version(value: bool) -> None:
    if value:
        typer.echo(f"ProbeGoblin {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    version: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Show the version and exit."
    ),
) -> None:
    """ProbeGoblin: safe first-pass checks for authorised web application tests."""


def fail(message: str, code: int = 2) -> None:
    err.print(f"[bold red]Error:[/] {message}")
    raise typer.Exit(code)


def parse_header(value: str) -> tuple[str, str]:
    if ":" not in value:
        fail(f"--header must look like 'Name: value', got {value!r}")
    name, _, rest = value.partition(":")
    if not name.strip():
        fail(f"--header has no name: {value!r}")
    return name.strip(), rest.strip()


def select_goblins(
    goblins: list[Goblin], flags: list[str], skip: str | None
) -> tuple[list[Goblin], list[str]]:
    by_flag = {g.flag: g for g in goblins}
    unknown = [f for f in flags if f not in by_flag]
    if unknown:
        known = ", ".join(f"--{f}" for f in by_flag)
        fail(f"no such option: {', '.join('--' + u for u in unknown)}. Module flags: {known}")
    chosen = [g for g in goblins if g.flag in flags] if flags else list(goblins)
    skipped: list[str] = []
    if skip:
        names = {s.strip().lower() for s in skip.split(",") if s.strip()}
        lookup = {g.flag: g for g in goblins} | {g.name.lower(): g for g in goblins}
        lookup |= {g.name.lower().removesuffix("goblin"): g for g in goblins}
        bad = [n for n in names if n not in lookup]
        if bad:
            fail(f"--skip: unknown module {', '.join(bad)}")
        drop = {lookup[n].name for n in names}
        skipped = [g.name for g in chosen if g.name in drop]
        chosen = [g for g in chosen if g.name not in drop]
    return chosen, skipped


def timestamped(path: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return path.with_name(f"{path.stem}-{stamp}{path.suffix}")


def choose_save_path(path: Path, assume_yes: bool) -> Path:
    if not path.exists():
        return path
    if not assume_yes and Confirm.ask(f"{path} exists. Overwrite?", default=False, console=err):
        return path
    new = timestamped(path)
    err.print(f"Results will be saved to {new}")
    return new


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    epilog=_module_epilog(),
)
def scan(
    ctx: typer.Context,
    targets: list[str] = typer.Argument(None, help="Target URL, for example https://example.com"),
    file: Path | None = typer.Option(None, "-f", "--file", help="File with one URL per line."),
    skip: str | None = typer.Option(None, "--skip", help="Modules to skip, e.g. waf,tls"),
    ip: str | None = typer.Option(None, "--ip", help="Connect to this IP, keep the hostname."),
    cookie: str | None = typer.Option(None, "--cookie", help="Cookie header to send."),
    header: list[str] = typer.Option(None, "--header", help="Extra header 'Name: value'."),
    rate: float | None = typer.Option(None, "--rate", help="Requests per second."),
    concurrency: int | None = typer.Option(None, "--concurrency", help="Parallel requests."),
    max_requests: int | None = typer.Option(None, "--max-requests", help="Request cap."),
    save: Path | None = typer.Option(None, "--save", help="Also write the output as text."),
    request_log: Path | None = typer.Option(None, "--request-log", help="Log each request."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip prompts."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="List passed checks too."),
    no_color: bool = typer.Option(False, "--no-color", help="Plain output."),
    config: Path | None = typer.Option(None, "--config", help="Config file to use."),
) -> None:
    """Scan one or more targets."""
    raw_targets: list[str] = []
    flags: list[str] = []
    for arg in [*(targets or []), *ctx.args]:
        if arg.startswith("--"):
            flags.append(arg[2:])
        elif arg.startswith("-"):
            fail(f"no such option: {arg}")
        else:
            raw_targets.append(arg)
    if file is not None:
        if ip:
            fail("--ip cannot be used with -f, pin one target at a time")
        if not file.is_file():
            fail(f"targets file not found: {file}")
        raw_targets.extend(read_targets_file(file))
    if not raw_targets:
        fail("give a target URL or -f targets.txt")
    if ip and len(raw_targets) > 1:
        fail("--ip can only be used with a single target")

    try:
        settings = load_settings(config)
    except (FileNotFoundError, ValueError) as exc:
        fail(str(exc))
    apply_options(settings, ip, cookie, header, rate, concurrency, max_requests, yes, verbose)

    goblins, user_skipped = select_goblins(discover(), flags, skip)
    console = Console(record=True, no_color=no_color, highlight=False)
    renderer = Renderer(console, verbose=verbose, secrets=settings.secret_values())
    save_path = choose_save_path(save, yes) if save else None

    renderer.banner()
    plans = asyncio.run(_plan(raw_targets, settings.pinned_ip))
    unavailable = [(g, r) for g in goblins if (r := g.unavailable_reason())]
    run = [g for g in goblins if not g.unavailable_reason()]
    estimate = estimate_requests(settings) + sum(g.estimate_requests(settings) for g in run)
    loads, browser_note = 0, None
    if any(g.uses_browser for g in run):
        browser_note = browser.unavailable_reason()
        if browser_note is None:
            frames = browser.MAX_AUTH_PAGES + 1 if any(g.flag == "clickjack" for g in run) else 0
            loads = min(settings.browser_page_limit, browser.MAX_AUTH_PAGES + 1 + frames)
            browser_note = "up to"
    else:
        browser_note = "no selected module uses the browser"
    renderer.preflight(
        plans,
        run,
        unavailable + [(g, "skipped with --skip") for g in discover() if g.name in user_skipped],
        estimate,
        settings.max_requests,
        loads,
        browser_note,
    )
    if all(p.error for p in plans):
        fail("no target can be scanned", code=1)
    if not yes and not Confirm.ask("Proceed?", default=False, console=console):
        console.print("Aborted. Nothing was sent.")
        raise typer.Exit(1)

    log = request_log.open("a", encoding="utf-8") if request_log else None
    try:
        results, interrupted = run_engine(settings, goblins, plans, log)
    finally:
        if log:
            log.close()
    for result in results:
        renderer.target(result)
    renderer.combined(results)
    renderer.sign_off(results)
    if save_path:
        save_path.write_text(console.export_text(clear=False), encoding="utf-8")
        err.print(f"Saved to {save_path}")
    if interrupted:
        raise typer.Exit(130)


def apply_options(
    settings: Settings,
    ip: str | None,
    cookie: str | None,
    header: list[str] | None,
    rate: float | None,
    concurrency: int | None,
    max_requests: int | None,
    yes: bool,
    verbose: bool,
) -> None:
    if ip:
        try:
            settings.pinned_ip = validate_ip(ip)
        except ValueError:
            fail(f"--ip is not an IP address: {ip}")
    if rate is not None:
        if rate <= 0:
            fail("--rate must be above 0")
        settings.rate = rate
    if concurrency is not None:
        if concurrency < 1:
            fail("--concurrency must be at least 1")
        settings.concurrency = concurrency
    if max_requests is not None:
        if max_requests < 1:
            fail("--max-requests must be at least 1")
        settings.max_requests = max_requests
    settings.cookie = cookie
    settings.headers = dict(parse_header(h) for h in header or [])
    settings.assume_yes = yes
    settings.verbose = verbose


async def _plan(raw_targets: list[str], pinned_ip: str | None):
    return list(await asyncio.gather(*(plan_target(t, pinned_ip) for t in raw_targets)))


def run_engine(settings, goblins, plans, log):
    status = err.status("Sharpening claws", spinner="dots12", spinner_style="green3")

    def progress(label: str) -> None:
        host, _, step = label.partition(": ")
        status.update(f"[green3]{host}[/] [grey62]>[/] [bold]{step or host}[/]")

    async def on_blocked(reason: str) -> str:
        status.stop()
        err.print(f"[bold gold1]The target keeps blocking requests:[/] {reason}")
        choice = await asyncio.to_thread(
            Prompt.ask,
            "Continue slower, continue, or stop?",
            choices=["slower", "continue", "stop"],
            default="stop",
            console=err,
        )
        status.start()
        return choice

    engine = Engine(settings, goblins, progress=progress, on_blocked=on_blocked, request_log=log)

    async def main():
        loop = asyncio.get_running_loop()

        def on_sigint() -> None:
            engine.interrupt()
            status.update("[bold red]Interrupted, stopping and printing results so far[/]")
            loop.remove_signal_handler(signal.SIGINT)

        loop.add_signal_handler(signal.SIGINT, on_sigint)
        try:
            return await engine.scan(plans)
        finally:
            loop.remove_signal_handler(signal.SIGINT)

    status.start()
    try:
        results = asyncio.run(main())
    except KeyboardInterrupt:
        status.stop()
        err.print("[bold red]Stopped immediately.[/] No results were printed.")
        raise typer.Exit(130) from None
    finally:
        status.stop()
    return results, engine.interrupted


@app.command("modules")
def modules_command() -> None:
    """List modules, their flags and whether they can run here."""
    console = Console(highlight=False)
    table = Table(header_style="bold green3", border_style="grey42")
    for column in ("Module", "Flag", "Checks", "Available"):
        table.add_column(column, overflow="fold")
    browser_reason = browser.unavailable_reason()
    for goblin in discover():
        reason = goblin.unavailable_reason()
        state = "[green]yes[/]" if reason is None else f"[red]{reason}[/]"
        if reason is None and goblin.uses_browser:
            state += (
                " [grey62](uses the browser)[/]"
                if browser_reason is None
                else f" [gold1](browser checks skipped: {browser_reason})[/]"
            )
        table.add_row(goblin.name, f"--{goblin.flag}", goblin.description, state)
    console.print(table)


VERSION_PATTERNS = {
    "testssl": r"testssl(?:\.sh)?\s+v?(\d[\w.~+-]*)",
    "wafw00f": r"WAFW00F you have is\s+\S*?v(\d[\w.]*)",
    "whatweb": r"WhatWeb version\s+(\d[\w.]*)",
}


def tool_version_text(tool: str, text: str | None) -> str:
    if not text:
        return "unknown"
    clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
    match = re.search(VERSION_PATTERNS[tool], clean)
    if match:
        return match.group(1)
    first = clean.strip().splitlines()[0][:60] if clean.strip() else "no output"
    return f"unknown (could not read version: {first})"


def data_dates() -> list[str]:
    from probegoblin.core import datafiles
    from probegoblin.modules import _fingerprints

    lines = []
    for label, base in (
        ("webappanalyzer", _fingerprints.data_dir()),
        ("RetireJS", datafiles.path("retirejs/jsrepository.json").parent),
    ):
        stamp = base / "RETRIEVED"
        when = stamp.read_text("utf-8").strip() if stamp.is_file() else "unknown"
        lines.append(f"{label}: {when}")
    own = ", ".join(
        f"{name} ({datafiles.origin(name)})"
        for name in ("js_runtime.yaml", "path_packs.toml", "favicons.toml", "cdn_ranges.toml")
    )
    lines.append(f"ProbeGoblin data: {own}")
    return lines


@app.command("doctor")
def doctor() -> None:
    """Check external tools, Playwright, Chromium and fingerprint data."""
    console = Console(highlight=False)
    table = Table(header_style="bold green3", border_style="grey42")
    for column in ("Component", "Found", "Version", "Install"):
        table.add_column(column, overflow="fold")
    checks = {"testssl": ("--version",), "wafw00f": ("--version",), "whatweb": ("--version",)}
    for tool, args in checks.items():
        path = find_tool(tool)
        version = tool_version_text(tool, asyncio.run(tool_version(tool, args))) if path else None
        table.add_row(
            tool,
            f"[green]{path}[/]" if path else "[red]no[/]",
            version or "-",
            "" if path else INSTALL_HINTS[tool],
        )
    found, version, detail = browser.chromium_status()
    table.add_row(
        "Chromium",
        f"[green]{detail}[/]" if found else f"[red]no[/] ({detail})",
        version or "-",
        "" if found else INSTALL_HINTS["chromium"],
    )
    console.print(table)
    for line in data_dates():
        console.print(line)
    keys = [
        k for k in ("NVD_API_KEY", "SNYK_TOKEN", "SNYK_ORG_ID", "GITHUB_TOKEN") if os.environ.get(k)
    ]
    console.print(
        f"API keys set: {', '.join(keys) if keys else 'none (OSV is used without a key)'}"
    )


@app.command("update")
def update_command() -> None:
    """Refresh RetireJS, webappanalyzer and ProbeGoblin data files."""
    from probegoblin.core.update import Updater

    console = Console(highlight=False)
    console.print("Updating fingerprint data. Each file is validated before it is used.")
    results = Updater().run()
    for item in results:
        mark = "[green]updated[/]" if item.ok else "[gold1]not updated[/]"
        console.print(f"  {item.name}: {mark} {item.detail}")
    if not any(item.ok for item in results):
        raise typer.Exit(1)


@app.command("setup")
def setup() -> None:
    """Download Chromium for the browser stage and list missing system tools."""
    console = Console(highlight=False)
    console.print("Downloading Chromium for Playwright...")
    code = subprocess.call([sys.executable, "-m", "playwright", "install", "chromium"])
    if code != 0:
        console.print("[red]Chromium download failed.[/] Run it again, or check your network.")
    missing = [t for t in ("testssl", "wafw00f", "whatweb") if find_tool(t) is None]
    if missing:
        packages = " ".join(INSTALL_HINTS[t].split()[-1] for t in missing)
        console.print(f"Missing tools. Install them with:\n  sudo apt install {packages}")
    else:
        console.print("[green]All external tools found.[/]")
    raise typer.Exit(code)


def main() -> None:
    app()

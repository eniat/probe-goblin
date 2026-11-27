from __future__ import annotations

import asyncio
import os
import signal
import sys
import time
import tomllib
from pathlib import Path

import pytest
import respx
from typer.testing import CliRunner

from probegoblin import cli
from probegoblin.core import preflight, registry
from probegoblin.core.config import Settings
from probegoblin.core.engine import Engine
from probegoblin.core.external import run_tool
from probegoblin.core.models import ModuleResult, Status
from probegoblin.core.preflight import plan_target, validate_target
from probegoblin.core.registry import Goblin
from probegoblin.output.terminal import Renderer
from tests.conftest import fast_settings, run

runner = CliRunner()
LOCAL = "http://127.0.0.1:8999/"


class SlowGoblin(Goblin):
    name = "SlowGoblin"
    flag = "slow"
    prefix = "SLW"

    async def run(self, ctx):
        await asyncio.sleep(30)
        return self.result()


class QuickGoblin(Goblin):
    name = "QuickGoblin"
    flag = "quick"
    prefix = "QCK"

    async def run(self, ctx):
        result = self.result()
        result.findings.append(
            self.finding(
                title="Quick",
                status=Status.OBSERVATION,
                affected_url=ctx.target,
                why_it_matters="x",
            )
        )
        return result


class MissingToolGoblin(Goblin):
    name = "MissingToolGoblin"
    flag = "missing"
    prefix = "MIS"

    def unavailable_reason(self):
        return "faketool not installed (sudo apt install faketool)"


def test_validate_target():
    assert validate_target("https://example.com") == ("https://example.com/", None)
    assert validate_target("example.com")[1].startswith("example.com: include the scheme")
    assert "only http and https" in validate_target("ftp://example.com/")[1]
    assert "credentials" in validate_target("https://user:pw@example.com/")[1]
    url, _ = validate_target("https://Example.com/Path?x=1")
    assert url == "https://example.com/Path?x=1"


def test_unresolvable_target_is_skipped(monkeypatch):
    async def fail(host, port):
        raise OSError("NXDOMAIN")

    monkeypatch.setattr(preflight, "resolve", fail)
    plan = run(plan_target("https://nope.example.invalid/"))
    assert plan.error == "nope.example.invalid does not resolve, target skipped"


def test_pinned_ip_allows_unresolvable_host(monkeypatch):
    async def fail(host, port):
        raise OSError("NXDOMAIN")

    monkeypatch.setattr(preflight, "resolve", fail)
    plan = run(plan_target("https://lab.internal/", pinned_ip="10.0.0.5"))
    assert plan.error is None and plan.ips == ["10.0.0.5"]
    assert "does not resolve" in plan.note


def test_cdn_label():
    assert preflight.cdn_for("104.16.1.1", None) == "Cloudflare"
    assert preflight.cdn_for("192.0.2.1", "server-1.foo.akamaitechnologies.com") == "Akamai"
    assert preflight.cdn_for("192.0.2.1", None) is None


@respx.mock
def test_preflight_prompt_blocks_requests():
    route = respx.route().respond(200)
    result = runner.invoke(cli.app, ["scan", LOCAL], input="n\n")
    assert result.exit_code == 1
    assert "Proceed?" in result.output
    assert "Nothing was sent" in result.output
    assert not route.called


def test_ip_with_file_rejected(tmp_path):
    targets = tmp_path / "t.txt"
    targets.write_text("https://a.example/\n# comment\n\nhttps://b.example/\n")
    result = runner.invoke(cli.app, ["scan", "-f", str(targets), "--ip", "192.0.2.1"])
    assert result.exit_code == 2
    assert "--ip cannot be used with -f" in result.output


def test_targets_file_parsing(tmp_path):
    targets = tmp_path / "t.txt"
    targets.write_text("https://a.example/\n# comment\n\n  https://b.example/  \n")
    assert preflight.read_targets_file(targets) == ["https://a.example/", "https://b.example/"]


def test_unknown_module_flag():
    result = runner.invoke(cli.app, ["scan", LOCAL, "--nonsense", "--yes"])
    assert result.exit_code == 2
    assert "no such option: --nonsense" in result.output


def test_module_selection_and_skip():
    goblins = registry.discover()
    chosen, _ = cli.select_goblins(goblins, ["headers", "cookies"], None)
    assert [g.flag for g in chosen] == ["headers", "cookies"]
    chosen, skipped = cli.select_goblins(goblins, [], "tech,clickjack")
    assert "TechnologyGoblin" in skipped and all(
        g.flag not in ("tech", "clickjack") for g in chosen
    )


def test_registry_discovers_modules_in_order():
    names = [g.name for g in registry.discover()]
    assert names[:4] == ["TechnologyGoblin", "HeaderGoblin", "CookieGoblin", "ClickjackGoblin"]


def test_drop_in_module(tmp_path, monkeypatch):
    from probegoblin import modules

    (tmp_path / "zz_dropin.py").write_text(
        "from probegoblin.core.registry import Goblin\n"
        "class DropInGoblin(Goblin):\n"
        "    name = 'DropInGoblin'\n    flag = 'dropin'\n    prefix = 'DRP'\n    order = 5\n"
    )
    monkeypatch.setattr(modules, "__path__", [*modules.__path__, str(tmp_path)])
    names = [g.name for g in registry.discover()]
    assert names[0] == "DropInGoblin"
    sys.modules.pop("probegoblin.modules.zz_dropin", None)


@respx.mock
def test_engine_interrupt_keeps_partial_results():
    respx.route().respond(200, html="<title>x</title>")
    plan = run(plan_target(LOCAL))
    engine = Engine(fast_settings(), [QuickGoblin(), SlowGoblin(), QuickGoblin()])

    async def go():
        task = asyncio.ensure_future(engine.scan([plan]))
        while not any(r for r in [engine._current] if r) or engine.interrupted:
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.3)
        engine.interrupt()
        return await task

    started = time.monotonic()
    [result] = run(go())
    assert time.monotonic() - started < 10
    assert result.interrupted
    assert result.modules[0].findings[0].title == "Quick"
    assert result.modules[1].not_assessed_reason == "interrupted"
    assert result.modules[2].not_assessed_reason == "interrupted"


@respx.mock
def test_ctrl_c_prints_partial_results(monkeypatch):
    respx.route().respond(200, html="<title>x</title>")

    class InterruptingGoblin(Goblin):
        name = "InterruptingGoblin"
        flag = "intr"
        prefix = "INT"

        async def run(self, ctx):
            os.kill(os.getpid(), signal.SIGINT)
            await asyncio.sleep(30)
            return self.result()

    monkeypatch.setattr(
        cli, "discover", lambda: [QuickGoblin(), InterruptingGoblin(), QuickGoblin()]
    )
    result = runner.invoke(cli.app, ["scan", LOCAL, "--yes", "--no-color", "--rate", "1000"])
    assert result.exit_code == 130
    assert "interrupted" in result.output
    assert "QuickGoblin" in result.output
    assert "Not assessed: interrupted" in result.output


@respx.mock
def test_missing_tool_reports_not_assessed():
    respx.route().respond(200, html="<title>x</title>")
    plan = run(plan_target(LOCAL))
    [result] = run(Engine(fast_settings(), [MissingToolGoblin()]).scan([plan]))
    assert "faketool not installed" in result.modules[0].not_assessed_reason


@respx.mock
def test_module_crash_is_contained():
    respx.route().respond(200, html="<title>x</title>")

    class BrokenGoblin(Goblin):
        name = "BrokenGoblin"
        flag = "broken"
        prefix = "BRK"

        async def run(self, ctx):
            raise ValueError("boom")

    plan = run(plan_target(LOCAL))
    [result] = run(Engine(fast_settings(), [BrokenGoblin(), QuickGoblin()]).scan([plan]))
    assert "ValueError: boom" in result.modules[0].not_assessed_reason
    assert result.modules[1].findings


def test_external_tool_time_limit_stops_hung_tool():
    started = time.monotonic()
    result = run(run_tool(["sleep", "30"], 0.5))
    assert result.timed_out
    assert time.monotonic() - started < 5


@respx.mock
def test_save_writes_plain_text_and_never_overwrites_with_yes(tmp_path, monkeypatch):
    respx.route().respond(200, html="<title>x</title>")
    monkeypatch.setattr(cli, "discover", lambda: [QuickGoblin()])
    out = tmp_path / "results.txt"
    out.write_text("old")
    result = runner.invoke(cli.app, ["scan", LOCAL, "--yes", "--rate", "1000", "--save", str(out)])
    assert result.exit_code == 0, result.output
    assert out.read_text() == "old"
    saved = [p for p in tmp_path.iterdir() if p.name.startswith("results-")]
    assert len(saved) == 1
    text = saved[0].read_text()
    assert "QuickGoblin" in text and "\x1b[" not in text


def test_supplied_secrets_are_masked(tmp_path):
    from rich.console import Console

    settings = Settings(cookie="session=SuperSecretValue123", headers={"X-Key": "hdr-secret-9"})
    console = Console(record=True, width=120)
    renderer = Renderer(console, secrets=settings.secret_values())
    result = ModuleResult(module="X")
    result.findings.append(
        QuickGoblin().finding(
            title="t",
            status=Status.ISSUE,
            affected_url="https://a/?k=SuperSecretValue123",
            observed="sent hdr-secret-9",
            why_it_matters="x",
        )
    )
    renderer._module(result)
    text = console.export_text()
    assert "SuperSecretValue123" not in text and "hdr-secret-9" not in text
    assert "<masked>" in text


def test_config_file_matches_defaults():
    path = Path(__file__).parent.parent / "config" / "probegoblin.toml"
    with path.open("rb") as handle:
        assert Settings.model_validate(tomllib.load(handle)) == Settings()


def test_version():
    result = runner.invoke(cli.app, ["--version"])
    assert result.output.strip() == "ProbeGoblin 0.1.0"


def test_doctor_version_parsing():
    assert cli.tool_version_text("whatweb", "WhatWeb version 0.5.5 ( https://x )") == "0.5.5"
    assert cli.tool_version_text("testssl", "    testssl       3.2rc3 from x") == "3.2rc3"
    wafw00f = "[+] The version of WAFW00F you have is \x1b[1;94mv2.4.2\x1b[0m"
    assert cli.tool_version_text("wafw00f", wafw00f) == "2.4.2"
    assert cli.tool_version_text("whatweb", "ruby: LoadError").startswith("unknown")


def test_sign_off_summarises_all_targets():
    from rich.console import Console

    from probegoblin.core.models import Finding, TargetResult

    console = Console(record=True, width=100)
    result = TargetResult(target="https://a/", host="a")
    module = ModuleResult(module="X")
    module.findings.append(
        Finding(module="X", title="t", status=Status.ISSUE, affected_url="u", why_it_matters="w")
    )
    result.modules.append(module)
    Renderer(console).sign_off([result, TargetResult(target="x", host="x", skipped_reason="dns")])
    text = console.export_text()
    assert "1 target poked" in text and "1 issue" in text and "over to you" in text


@pytest.mark.parametrize(
    ("width", "expect_title", "title_rows"),
    [(140, True, 8), (100, True, 16), (60, False, 0)],
)
def test_banner_fits_the_terminal(width, expect_title, title_rows):
    import io

    from rich.console import Console

    from probegoblin.output import art

    buffer = io.StringIO()
    Renderer(Console(width=width, file=buffer)).banner()
    lines = [line.rstrip() for line in buffer.getvalue().splitlines()]
    assert max(len(line) for line in lines) <= width
    assert sum("888" in line for line in lines) >= title_rows if expect_title else True
    assert not any("8888888b." in line for line in lines) if not expect_title else True
    feet = art.GOBLIN[-1].strip()
    feet_line = next(line for line in lines if feet in line)
    if expect_title:
        assert "888" in feet_line  # feet sit on the title's bottom line
    assert any("Poking around where it matters" in line for line in lines)


def test_banner_on_a_tiny_terminal_is_just_the_tagline():
    import io

    from rich.console import Console

    buffer = io.StringIO()
    Renderer(Console(width=30, file=buffer)).banner()
    assert "⣿" not in buffer.getvalue() and "ProbeGoblin" in buffer.getvalue()

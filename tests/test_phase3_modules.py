from __future__ import annotations

import stat
import time

import pytest
import respx

from probegoblin.core.models import Status
from probegoblin.core.registry import discover
from probegoblin.modules import tls as tls_module
from probegoblin.modules import waf as waf_module
from probegoblin.modules.direct_ip import IPGoblin, ip_url
from probegoblin.modules.methods import MethodsGoblin
from probegoblin.modules.tls import TLSGoblin, parse_testssl, summary
from probegoblin.modules.waf import WAFGoblin, parse_wafw00f
from tests.conftest import FIXTURES, TARGET, fast_settings, make_ctx, make_page, run


def titles(result, status):
    return {f.title for f in result.findings if f.status == status}


def fake_tool(tmp_path, monkeypatch, module, name: str, script: str):
    """Put an executable script on a private PATH and point find_tool at it."""
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(module, "find_tool", lambda tool: str(path))
    return path


def landing_ctx(settings=None, target=TARGET):
    return make_ctx(
        [make_page(target, body="<title>Home</title>", source="landing")], settings, target
    )


# testssl parsing


def test_parse_real_testssl_output():
    items = parse_testssl((FIXTURES / "testssl" / "selfsigned.json").read_text())
    assert len(items) == 158
    by_id = {i.id: i for i in items}
    assert by_id["cert_chain_of_trust"].severity == "CRITICAL"
    text = summary(items)
    assert text.startswith("TLS 1.2, 1.3 | certificate valid until 2026-12-26")
    assert "testssl grade T" in text


def test_parse_failure_raises():
    with pytest.raises(ValueError):
        parse_testssl("not json")


def test_tls_module_with_real_output(tmp_path, monkeypatch):
    fixture = FIXTURES / "testssl" / "selfsigned.json"
    fake_tool(tmp_path, monkeypatch, tls_module, "testssl", f'cp "{fixture}" "$2"\n')
    ctx = landing_ctx()
    result = run(TLSGoblin().run(ctx))
    issues = titles(result, Status.ISSUE)
    assert {"Certificate chain not trusted", "Certificate does not match the hostname"} <= issues
    assert "Certificate expiry date" not in issues  # merged into Certificate expiry
    assert "TLS 1.2, 1.3" in ctx.summary["tls"]
    hsts = [f for f in result.findings if "HSTS" in f.title or "BREACH" in f.title]
    assert hsts == []  # owned by HeaderGoblin and CompressionGoblin
    issue = [f for f in result.findings if f.status == Status.ISSUE][0]
    assert issue.reproduce[0].startswith("testssl -S ")
    assert result.tables[0].rows


def test_tls_command_is_defaults_plus_jsonfile(tmp_path):
    ctx = landing_ctx()
    argv = TLSGoblin().command(ctx, tmp_path / "x.json")
    assert argv[1:] == ["--jsonfile", str(tmp_path / "x.json"), TARGET]
    pinned = landing_ctx(fast_settings(pinned_ip="192.0.2.5"))
    argv = TLSGoblin().command(pinned, tmp_path / "x.json")
    assert argv[1:] == ["--jsonfile", str(tmp_path / "x.json"), "--ip", "192.0.2.5", TARGET]


def test_tls_fatal_is_not_assessed(tmp_path, monkeypatch):
    fixture = FIXTURES / "testssl" / "closed.json"
    fake_tool(tmp_path, monkeypatch, tls_module, "testssl", f'cp "{fixture}" "$2"\nexit 246\n')
    result = run(TLSGoblin().run(landing_ctx()))
    assert result.not_assessed_reason.startswith("testssl.sh stopped: Can't connect")


def test_tls_unparsable_output(tmp_path, monkeypatch):
    fake_tool(tmp_path, monkeypatch, tls_module, "testssl", 'echo "garbage" > "$2"\n')
    result = run(TLSGoblin().run(landing_ctx()))
    assert result.not_assessed_reason == "could not parse testssl.sh output"


def test_tls_time_limit_stops_hung_tool(tmp_path, monkeypatch):
    fake_tool(tmp_path, monkeypatch, tls_module, "testssl", "sleep 60\n")
    settings = fast_settings()
    settings.tool_limits.testssl = 1
    started = time.monotonic()
    result = run(TLSGoblin().run(landing_ctx(settings)))
    assert result.not_assessed_reason == "timed out after 1 seconds"
    assert time.monotonic() - started < 6


def test_tls_skipped_for_http_target():
    ctx = landing_ctx(target="http://app.example.com/")
    result = run(TLSGoblin().run(ctx))
    assert result.not_assessed_reason == "target uses plain HTTP"


def test_missing_tools_reported_with_install_command(monkeypatch):
    monkeypatch.setattr(tls_module, "find_tool", lambda tool: None)
    monkeypatch.setattr(waf_module, "find_tool", lambda tool: None)
    assert "sudo apt install testssl.sh" in TLSGoblin().unavailable_reason()
    assert "sudo apt install wafw00f" in WAFGoblin().unavailable_reason()


# wafw00f


def test_parse_real_wafw00f_output():
    entries = parse_wafw00f((FIXTURES / "wafw00f" / "cloudflare.json").read_text())
    assert entries[0]["detected"] is True and entries[0]["firewall"] == "Cloudflare"
    assert parse_wafw00f((FIXTURES / "wafw00f" / "down.json").read_text()) == []


def test_waf_detected_and_corroborated(tmp_path, monkeypatch):
    fixture = FIXTURES / "wafw00f" / "cloudflare.json"
    fake_tool(tmp_path, monkeypatch, waf_module, "wafw00f", f'cp "{fixture}" "$3"\n')
    landing = make_page(
        TARGET, headers=[("CF-RAY", "8a1b-LHR"), ("Server", "cloudflare")], source="landing"
    )
    ctx = make_ctx([landing])
    result = run(WAFGoblin().run(ctx))
    assert "WAF identified: Cloudflare" in titles(result, Status.OBSERVATION)
    assert ctx.summary["waf"].startswith("Cloudflare (wafw00f, CF-RAY header")
    assert not any("indicators" in t for t in titles(result, Status.OBSERVATION))


def test_waf_none_never_says_no_waf(tmp_path, monkeypatch):
    fixture = FIXTURES / "wafw00f" / "none.json"
    fake_tool(tmp_path, monkeypatch, waf_module, "wafw00f", f'cp "{fixture}" "$3"\n')
    ctx = landing_ctx()
    result = run(WAFGoblin().run(ctx))
    assert ctx.summary["waf"] == "No WAF identified by wafw00f"
    assert all(f.title != "No WAF" for f in result.findings)


def test_waf_site_down(tmp_path, monkeypatch):
    fixture = FIXTURES / "wafw00f" / "down.json"
    stderr = FIXTURES / "wafw00f" / "down.stderr"
    fake_tool(
        tmp_path, monkeypatch, waf_module, "wafw00f", f'cp "{fixture}" "$3"\ncat "{stderr}" >&2\n'
    )
    result = run(WAFGoblin().run(landing_ctx()))
    na = [f for f in result.findings if f.status == Status.NOT_ASSESSED]
    assert na and "Something went wrong" in na[0].observed


def test_waf_not_run_when_pinned(tmp_path, monkeypatch):
    marker = tmp_path / "ran"
    fake_tool(tmp_path, monkeypatch, waf_module, "wafw00f", f'touch "{marker}"\n')
    result = run(WAFGoblin().run(landing_ctx(fast_settings(pinned_ip="192.0.2.5"))))
    assert not marker.exists()
    assert any("cannot be pinned" in (f.observed or "") for f in result.findings)


def test_waf_header_only_evidence(tmp_path, monkeypatch):
    fixture = FIXTURES / "wafw00f" / "none.json"
    fake_tool(tmp_path, monkeypatch, waf_module, "wafw00f", f'cp "{fixture}" "$3"\n')
    landing = make_page(
        TARGET, headers=[("Set-Cookie", "incap_ses_123=abc; path=/")], source="landing"
    )
    result = run(WAFGoblin().run(make_ctx([landing])))
    assert "Imperva Incapsula indicators in responses" in titles(result, Status.OBSERVATION)


# MethodsGoblin


@respx.mock
def test_methods_only_sends_options():
    respx.options(TARGET).respond(
        200, headers={"Allow": "GET, HEAD, OPTIONS, PUT, DELETE", "DAV": "1,2"}
    )
    result = run(MethodsGoblin().run(landing_ctx()))
    manual = [f for f in result.findings if f.status == Status.MANUAL_CHECK]
    assert manual and "PUT" in manual[0].observed and "DELETE" in manual[0].observed
    assert "not tested" in manual[0].title
    assert {c.request.method for c in respx.calls} == {"OPTIONS"}


@respx.mock
def test_methods_safe_set_is_ok():
    respx.options(TARGET).respond(204, headers={"Allow": "GET, HEAD, OPTIONS"})
    result = run(MethodsGoblin().run(landing_ctx()))
    assert titles(result, Status.MANUAL_CHECK) == set()


# IPGoblin


def test_ip_url_formats():
    assert ip_url("http", "192.0.2.1") == "http://192.0.2.1/"
    assert ip_url("https", "2001:db8::1") == "https://[2001:db8::1]/"


@respx.mock
def test_direct_ip_access():
    respx.get("http://192.0.2.10/").respond(200, html="<title>Home</title>")
    respx.get("https://192.0.2.10/").respond(403, html="<title>Forbidden</title>")
    ctx = landing_ctx()
    ctx.ips = ["192.0.2.10"]
    ctx.client.scope.ips = ["192.0.2.10"]
    result = run(IPGoblin().run(ctx))
    rows = dict(result.tables[0].rows)
    assert rows["http://192.0.2.10/"] == "serves the same application"
    assert rows["https://192.0.2.10/"].startswith("responds with different content")
    assert "Direct IP access possible, serves the same application" in titles(
        result, Status.OBSERVATION
    )


# Order


def test_external_tools_run_after_http_modules_waf_last():
    goblins = discover()
    stages = [g.stage for g in goblins]
    assert stages == sorted(stages, key=lambda s: s != "http")
    assert goblins[-1].name == "WAFGoblin"
    assert goblins[-2].name == "TLSGoblin"


def test_ids_number_problems_first():
    from probegoblin.core.models import ModuleResult
    from probegoblin.core.registry import assign_ids

    goblin = MethodsGoblin()
    result = ModuleResult(module="x")
    for status in (Status.OK, Status.ISSUE, Status.OBSERVATION):
        result.findings.append(
            goblin.finding(title=status.value, status=status, affected_url="u", why_it_matters="w")
        )
    assign_ids(goblin, result)
    assert [(f.finding_id, f.status) for f in result.findings][0] == ("MTH-001", Status.ISSUE)


def test_no_tool_runs_concurrently(tmp_path):
    import asyncio

    from probegoblin.core.external import run_tool

    log = tmp_path / "log"
    script = tmp_path / "t.sh"
    script.write_text(f'#!/bin/sh\necho start >> "{log}"\nsleep 0.3\necho end >> "{log}"\n')
    script.chmod(0o755)

    async def go():
        await asyncio.gather(run_tool([str(script)], 5), run_tool([str(script)], 5))

    run(go())
    assert log.read_text().split() == ["start", "end", "start", "end"]


def test_ctrl_c_stops_external_tool(tmp_path):
    import asyncio
    import os

    from probegoblin.core.external import run_tool

    pidfile = tmp_path / "pid"
    script = tmp_path / "hang.sh"
    script.write_text(f'#!/bin/sh\necho $$ > "{pidfile}"\nsleep 60\n')
    script.chmod(0o755)

    async def go():
        task = asyncio.ensure_future(run_tool([str(script)], 120))
        while not pidfile.exists():
            await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run(go())
    pid = int(pidfile.read_text())
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)

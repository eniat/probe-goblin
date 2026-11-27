from __future__ import annotations

from probegoblin.core.models import Status
from probegoblin.modules import _fingerprints as fingerprints
from probegoblin.modules import technology
from probegoblin.modules.technology import TechnologyGoblin, favicon_hash, parse_whatweb
from tests.conftest import FIXTURES, TARGET, make_ctx, make_page, run

WORDPRESS = (
    '<html><head><meta name="generator" content="WordPress 6.4.2">'
    '<link rel="stylesheet" href="/wp-content/themes/x/style.css"></head>'
    '<body><script src="/wp-includes/js/jquery/jquery.min.js"></script></body></html>'
)


def tech_run(pages, monkeypatch, whatweb=None):
    monkeypatch.setattr(technology, "find_tool", lambda name: whatweb)
    ctx = make_ctx(pages)
    return run(TechnologyGoblin().run(ctx)), ctx


def test_favicon_hash_matches_shodan_values():
    assert favicon_hash((FIXTURES / "favicons" / "jenkins.ico").read_bytes()) == 81586312
    assert favicon_hash((FIXTURES / "favicons" / "grafana.png").read_bytes()) == 2123863676


def test_version_template():
    pattern = fingerprints.parse_pattern(r"nginx(?:/([\d.]+))?\;version:\1")
    assert pattern.match("nginx/1.25.3") == (True, "1.25.3")
    assert pattern.match("nginx") == (True, None)
    ternary = fingerprints.parse_pattern(r"foo(bar)?\;version:\1?2.0:1.0")
    assert ternary.match("foobar") == (True, "2.0")
    assert ternary.match("foo") == (True, "1.0")


def test_detects_stack(monkeypatch):
    landing = make_page(
        TARGET,
        headers=[("Server", "nginx/1.18.0"), ("X-Powered-By", "PHP/7.4.33")],
        body=WORDPRESS,
        source="landing",
    )
    result, ctx = tech_run([landing], monkeypatch)
    found = {t.name: t.version for t in ctx.tech}
    assert found["Nginx"] == "1.18.0"
    assert found["PHP"] == "7.4.33"
    assert found["WordPress"] == "6.4.2"
    assert "MySQL" in found  # implied by WordPress
    issues = {f.title for f in result.findings if f.status == Status.ISSUE}
    assert "Version disclosed in Server header" in issues
    assert "Version disclosed in X-Powered-By header" in issues


def test_header_without_version_is_observation(monkeypatch):
    landing = make_page(
        TARGET, headers=[("Server", "nginx")], body="<html></html>", source="landing"
    )
    result, _ = tech_run([landing], monkeypatch)
    hit = [f for f in result.findings if f.title.startswith("Server header")]
    assert hit and hit[0].status == Status.OBSERVATION


def test_debug_token_is_issue(monkeypatch):
    landing = make_page(
        TARGET,
        headers=[
            ("X-Debug-Token", "a1b2c3"),
            ("X-Debug-Token-Link", "https://app/_profiler/a1b2c3"),
        ],
        source="landing",
    )
    result, _ = tech_run([landing], monkeypatch)
    issues = {f.title for f in result.findings if f.status == Status.ISSUE}
    assert {"X-Debug-Token header present", "X-Debug-Token-Link header present"} <= issues


def test_missing_whatweb_is_not_assessed(monkeypatch):
    result, _ = tech_run([make_page(TARGET, source="landing")], monkeypatch, whatweb=None)
    na = [f for f in result.findings if f.title == "whatweb second opinion"]
    assert na and na[0].status == Status.NOT_ASSESSED
    assert "sudo apt install whatweb" in na[0].observed


def test_browser_fingerprints_reported_as_skipped(monkeypatch):
    result, _ = tech_run([make_page(TARGET, source="landing")], monkeypatch)
    titles = {f.title for f in result.findings if f.status == Status.NOT_ASSESSED}
    assert "JavaScript and DOM fingerprints" in titles


def test_favicon_match(monkeypatch):
    landing = make_page(TARGET, source="landing")
    icon = make_page(
        f"{TARGET}favicon.ico",
        headers=[("Content-Type", "image/x-icon")],
        body=(FIXTURES / "favicons" / "jenkins.ico").read_bytes(),
        source="favicon",
    )
    ctx = make_ctx([landing, icon])
    ctx.store.favicon = icon
    monkeypatch.setattr(technology, "find_tool", lambda name: None)
    result = run(TechnologyGoblin().run(ctx))
    assert ctx.summary["favicon_hash"] == 81586312
    assert any("Jenkins" in f.title for f in result.findings)


def test_parse_whatweb_fixture():
    entries = parse_whatweb((FIXTURES / "whatweb" / "wordpress_a1.json").read_text())
    plugins = entries[0]["plugins"]
    assert plugins["WordPress"]["version"] == ["6.2"]


def test_parse_whatweb_line_format():
    text = '[\n{"target":"a","plugins":{"X":{}}},\n{"target":"b","plugins":{}}\n]'
    assert len(parse_whatweb(text)) == 2

from __future__ import annotations

from probegoblin.core import cookies as cookielib
from probegoblin.core import csp
from probegoblin.core.models import Status
from probegoblin.modules.clickjack import ClickjackGoblin, framing_state
from tests.conftest import TARGET, make_ctx, make_page, run

HTML = "<html><title>Home</title></html>"


def state(headers, body=HTML):
    page = make_page(TARGET, headers=headers, body=body)
    from probegoblin.core.htmlparse import parse_html

    return framing_state(page, csp.page_policies(page, parse_html(body)))


def test_framing_states():
    assert state([])[0] is True
    assert state([("X-Frame-Options", "DENY")])[0] is False
    assert state([("X-Frame-Options", "sameorigin")])[0] is False
    assert state([("Content-Security-Policy", "frame-ancestors 'none'")])[0] is False
    assert (
        state([("Content-Security-Policy", "frame-ancestors 'self' https://a.example")])[0] is False
    )


def test_allow_from_and_invalid_xfo_are_frameable():
    frameable, summary, notes = state([("X-Frame-Options", "ALLOW-FROM https://a.example")])
    assert frameable and "unsupported" in summary
    frameable, _, notes = state([("X-Frame-Options", "yes please")])
    assert frameable and "invalid" in notes[0]


def test_frame_ancestors_wins_over_xfo():
    frameable, _, notes = state(
        [("X-Frame-Options", "DENY"), ("Content-Security-Policy", "frame-ancestors *")]
    )
    assert frameable
    assert any("overridden" in n for n in notes)


def test_meta_frame_ancestors_ignored():
    body = (
        '<html><head><meta http-equiv="Content-Security-Policy" '
        "content=\"frame-ancestors 'none'\"></head></html>"
    )
    frameable, _, notes = state([], body=body)
    assert frameable
    assert any("meta" in n for n in notes)


def test_report_only_not_enforced():
    frameable, _, notes = state([("Content-Security-Policy-Report-Only", "frame-ancestors 'none'")])
    assert frameable and any("Report-Only" in n for n in notes)


def test_conflicting_xfo_treated_as_deny():
    frameable, summary, _ = state([("X-Frame-Options", "DENY"), ("X-Frame-Options", "SAMEORIGIN")])
    assert not frameable and "treated as DENY" in summary


def test_any_frameable_page_is_an_issue_with_poc():
    about = make_page(f"{TARGET}about", body="<title>About</title>", source="robots_sitemap")
    login = make_page(
        f"{TARGET}login",
        headers=[("X-Frame-Options", "DENY")],
        body="<title>Login</title><form><input type=password></form>",
    )
    landing = make_page(TARGET, headers=[("X-Frame-Options", "DENY")], body=HTML, source="landing")
    ctx = make_ctx([landing, login, about])
    result = run(ClickjackGoblin().run(ctx))
    issues = [f for f in result.findings if f.status == Status.ISSUE]
    assert len(issues) == 1 and issues[0].affected_url == f"{TARGET}about"
    assert any("<iframe src=" in step for step in issues[0].reproduce)
    na = [f for f in result.findings if f.status == Status.NOT_ASSESSED]
    assert na and na[0].title == "Browser framing confirmation"


def test_samesite_context_in_why():
    ctx = make_ctx([make_page(TARGET, body=HTML, source="landing")])
    ctx.shared["session_cookies"] = [cookielib.parse_set_cookie("sid=a; SameSite=Lax")]
    result = run(ClickjackGoblin().run(ctx))
    issue = [f for f in result.findings if f.status == Status.ISSUE][0]
    assert "SameSite=Lax" in issue.why_it_matters
    assert "unlikely" in issue.why_it_matters

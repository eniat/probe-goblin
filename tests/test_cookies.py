from __future__ import annotations

from probegoblin.core import cookies as cookielib
from probegoblin.core.models import Status
from probegoblin.modules.cookies import CookieGoblin
from tests.conftest import TARGET, make_ctx, make_page, run


def scan(*set_cookies, url=TARGET, extra_pages=()):
    headers = [("Set-Cookie", value) for value in set_cookies]
    ctx = make_ctx([make_page(url, headers=headers, source="landing"), *extra_pages], target=url)
    return run(CookieGoblin().run(ctx)), ctx


def titles(result, status):
    return {f.title for f in result.findings if f.status == status}


def test_parse_set_cookie():
    cookie = cookielib.parse_set_cookie(
        "sid=abc123; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax"
    )
    assert cookie.name == "sid" and cookie.value == "abc123"
    assert cookie.secure and cookie.httponly and cookie.samesite == "Lax"
    assert cookie.persistent and cookie.path == "/"
    assert cookielib.parse_set_cookie("garbage") is None


def test_purpose():
    assert cookielib.purpose("PHPSESSID") == cookielib.SESSION
    assert cookielib.purpose("JSESSIONID") == cookielib.SESSION
    assert cookielib.purpose("connect.sid") == cookielib.SESSION
    assert cookielib.purpose("XSRF-TOKEN") == cookielib.CSRF
    assert cookielib.purpose("_ga") == cookielib.ANALYTICS
    assert cookielib.purpose("AWSALB") == cookielib.INFRASTRUCTURE
    assert cookielib.purpose("lang") == cookielib.PREFERENCE
    assert cookielib.purpose("__Host-session") == cookielib.SESSION
    assert cookielib.purpose("banana") == cookielib.UNKNOWN


def test_insecure_session_cookie():
    result, ctx = scan("PHPSESSID=abcdef123456; Path=/")
    issues = titles(result, Status.ISSUE)
    assert "Cookie PHPSESSID without Secure" in issues
    assert "Session cookie PHPSESSID without HttpOnly" in issues
    assert "Cookie PHPSESSID without SameSite" in titles(result, Status.OBSERVATION)
    assert ctx.shared["session_cookies"][0].name == "PHPSESSID"


def test_secret_value_redacted():
    result, _ = scan("PHPSESSID=abcdef123456; Path=/")
    for finding in result.findings:
        assert "abcdef123456" not in (finding.observed or "")


def test_analytics_cookie_is_not_an_issue():
    result, _ = scan("_ga=GA1.2.123; Max-Age=600")
    assert titles(result, Status.ISSUE) == set()
    assert "Cookie _ga without Secure" in titles(result, Status.OBSERVATION)


def test_csrf_cookie_readable_by_script_is_fine():
    result, _ = scan("XSRF-TOKEN=abc; Secure; SameSite=Lax")
    assert titles(result, Status.ISSUE) == set()


def test_samesite_none_without_secure():
    result, _ = scan("sid=abc; HttpOnly; SameSite=None")
    assert "Cookie sid has SameSite=None without Secure" in titles(result, Status.ISSUE)


def test_prefix_rules():
    result, _ = scan("__Host-sid=abc; Secure; HttpOnly; Path=/app; SameSite=Lax")
    assert "Cookie __Host-sid breaks its prefix rules" in titles(result, Status.ISSUE)
    result, _ = scan("__Secure-x=abc; HttpOnly; SameSite=Lax")
    assert "Cookie __Secure-x breaks its prefix rules" in titles(result, Status.ISSUE)


def test_parent_domain_and_persistence():
    result, _ = scan(
        "sessionid=abc; Domain=.example.com; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000"
    )
    observations = titles(result, Status.OBSERVATION)
    assert "Cookie sessionid scoped to the parent domain" in observations
    assert "Session cookie sessionid is persistent" in observations
    assert titles(result, Status.ISSUE) == set()


def test_duplicate_with_different_attributes():
    login = make_page(
        f"{TARGET}login", headers=[("Set-Cookie", "sid=zzz; Secure; HttpOnly; SameSite=Lax")]
    )
    result, _ = scan("sid=abc; Secure; HttpOnly; SameSite=Strict", extra_pages=[login])
    assert "Cookie sid set with different attributes" in titles(result, Status.OBSERVATION)


def test_http_site_does_not_demand_secure():
    result, _ = scan("PHPSESSID=abc; HttpOnly; SameSite=Lax", url="http://app.example.com/")
    assert "Cookie PHPSESSID without Secure" not in titles(result, Status.ISSUE)


def test_manual_check_always_present_and_no_cookies():
    result, _ = scan()
    assert result.not_assessed_reason == "no cookies returned"
    manual = [f for f in result.findings if f.status == Status.MANUAL_CHECK]
    assert manual and manual[0].manual_steps and manual[0].reproduce


def test_cookies_on_redirect_hops_are_seen():
    from probegoblin.core.models import Hop

    page = make_page(TARGET, source="landing")
    page.chain.insert(
        0, Hop(url=f"{TARGET}start", status=302, headers=[("Set-Cookie", "JSESSIONID=x1y2z3")])
    )
    ctx = make_ctx([page])
    result = run(CookieGoblin().run(ctx))
    assert any(row[0] == "JSESSIONID" for row in result.tables[0].rows)

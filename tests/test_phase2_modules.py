from __future__ import annotations

import json

import respx

from probegoblin.core.models import Status
from probegoblin.core.secrets import find_secrets, mask, redact_text
from probegoblin.modules.api import APIGoblin
from probegoblin.modules.cache import CacheGoblin
from probegoblin.modules.compression import CompressionGoblin
from probegoblin.modules.cors import CORSGoblin
from probegoblin.modules.disclosure import DisclosureGoblin, parse_security_txt
from probegoblin.modules.host import HostGoblin
from probegoblin.modules.leaks import LeakGoblin
from probegoblin.modules.redirects import RedirectGoblin
from probegoblin.modules.robots import RobotsGoblin
from tests.conftest import TARGET, fast_settings, make_ctx, make_page, run

AWS = "AKIA" + "IOSFODNN7EXAMPLE"
LOGIN_HTML = (
    "<title>Login</title><form method=post><input type=hidden name=_token "
    'value="abcdefghijklmnop1234"><input type=password name=p></form>'
)


def statuses(result):
    return {(f.title, f.status) for f in result.findings}


def titles(result, status):
    return {f.title for f in result.findings if f.status == status}


# CacheGoblin


def cache_run(headers, settings=None):
    landing = make_page(TARGET, source="landing")
    login = make_page(f"{TARGET}login", headers=headers, body=LOGIN_HTML)
    ctx = make_ctx([landing, login], settings=settings)
    return run(CacheGoblin().run(ctx))


def test_cache_public_on_login_is_issue():
    result = cache_run([("Cache-Control", "public, max-age=3600")])
    assert "Sensitive page cacheable by shared caches" in titles(result, Status.ISSUE)


def test_cache_no_cache_without_no_store():
    result = cache_run([("Cache-Control", "no-cache")])
    assert "no-cache used without no-store" in titles(result, Status.ISSUE)


def test_cache_no_store_is_ok():
    result = cache_run([("Cache-Control", "no-store")])
    assert titles(result, Status.ISSUE) == set()
    assert "Caching of sensitive page" in titles(result, Status.OK)


def test_cache_missing_header_judged_by_content():
    result = cache_run([("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")])
    assert "No Cache-Control on sensitive page" in titles(result, Status.ISSUE)
    plain = make_page(f"{TARGET}account", body="<title>Account</title>")
    ctx = make_ctx([make_page(TARGET, source="landing"), plain])
    assert titles(run(CacheGoblin().run(ctx)), Status.ISSUE) == set()


@respx.mock
def test_cache_compares_without_session():
    route = respx.get(f"{TARGET}login").respond(200, html=LOGIN_HTML)
    result = cache_run([("Cache-Control", "no-store")], settings=fast_settings(cookie="s=abcd1234"))
    assert route.called
    assert "cookie" not in route.calls.last.request.headers
    assert "Same response with and without the supplied session" in titles(
        result, Status.OBSERVATION
    )


# CompressionGoblin


def test_breach_manual_check_only_with_token():
    page = make_page(
        f"{TARGET}login", headers=[("Content-Encoding", "gzip")], body=LOGIN_HTML, source="landing"
    )
    result = run(CompressionGoblin().run(make_ctx([page])))
    assert "BREACH conditions may be present" in titles(result, Status.MANUAL_CHECK)
    plain = make_page(
        TARGET, headers=[("Content-Encoding", "gzip")], body="<p>hi</p>", source="landing"
    )
    result = run(CompressionGoblin().run(make_ctx([plain])))
    assert titles(result, Status.MANUAL_CHECK) == set()
    assert "HTTP compression enabled (gzip)" in titles(result, Status.OBSERVATION)


# CORSGoblin


def cors_ctx():
    landing = make_page(TARGET, source="landing")
    return make_ctx([landing])


@respx.mock
def test_cors_reflection_with_credentials():
    def respond(request):
        origin = request.headers.get("origin")
        return respx.MockResponse(
            200,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            },
        )

    respx.get(TARGET).mock(side_effect=respond)
    result = run(CORSGoblin().run(cors_ctx()))
    issues = titles(result, Status.ISSUE)
    assert "CORS reflects any origin with credentials" in issues
    assert "CORS accepts the null origin with credentials" in issues
    assert "Reflected CORS response without Vary: Origin" in titles(result, Status.OBSERVATION)
    hit = [f for f in result.findings if f.status == Status.ISSUE][0]
    assert hit.manual_steps and "valid session cookie" in hit.manual_steps[0]
    origins = {c.request.headers["origin"] for c in respx.calls}
    assert origins == {
        "https://probegoblin.invalid",
        "null",
        "https://app.example.com.probegoblin.invalid",
        "https://probegoblinapp.example.com",
    }


@respx.mock
def test_cors_suffix_only_validation():
    def respond(request):
        origin = request.headers.get("origin", "")
        headers = {}
        if origin.endswith("app.example.com"):
            headers = {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
        return respx.MockResponse(200, headers=headers)

    respx.get(TARGET).mock(side_effect=respond)
    result = run(CORSGoblin().run(cors_ctx()))
    assert "CORS origin check can be bypassed with a crafted domain" in titles(
        result, Status.OBSERVATION
    )


@respx.mock
def test_cors_clean():
    respx.get(TARGET).respond(200)
    result = run(CORSGoblin().run(cors_ctx()))
    assert titles(result, Status.ISSUE) == set() and titles(result, Status.OBSERVATION) == set()


@respx.mock
def test_cors_wildcard_is_observation():
    respx.get(TARGET).respond(200, headers={"Access-Control-Allow-Origin": "*"})
    result = run(CORSGoblin().run(cors_ctx()))
    assert "CORS allows any origin (wildcard)" in titles(result, Status.OBSERVATION)
    assert titles(result, Status.ISSUE) == set()


# RedirectGoblin


@respx.mock
def test_http_redirects_permanently_to_https():
    respx.get("http://app.example.com/").respond(301, headers={"Location": TARGET})
    respx.get(TARGET).respond(200)
    result = run(RedirectGoblin().run(make_ctx([make_page(TARGET, source="landing")])))
    assert "HTTP redirects to HTTPS" in titles(result, Status.OK)
    assert titles(result, Status.ISSUE) == set()


@respx.mock
def test_http_served_without_redirect():
    respx.get("http://app.example.com/").respond(200, html="<title>Home</title>")
    result = run(RedirectGoblin().run(make_ctx([make_page(TARGET, source="landing")])))
    assert "Site served over plain HTTP without redirect" in titles(result, Status.ISSUE)


@respx.mock
def test_temporary_redirect_and_mixed_content():
    respx.get("http://app.example.com/").respond(302, headers={"Location": TARGET})
    respx.get(TARGET).respond(200)
    body = (
        '<script src="http://cdn.example.net/a.js"></script><img src="http://img.example.net/b.png">'
        '<form action="http://app.example.com/login"></form><a href="/x?redirect_uri=/y">a</a>'
    )
    landing = make_page(TARGET, body=body, source="landing")
    ctx = make_ctx([landing])
    ctx.store.url_params.append((TARGET, f"{TARGET}x?redirect_uri=/y", "redirect_uri"))
    result = run(RedirectGoblin().run(ctx))
    assert "HTTP to HTTPS redirect is not permanent" in titles(result, Status.OBSERVATION)
    assert {"Active mixed content", "Form submits over plain HTTP"} <= titles(result, Status.ISSUE)
    assert "Passive mixed content" in titles(result, Status.OBSERVATION)
    manual = [f for f in result.findings if f.status == Status.MANUAL_CHECK]
    assert manual and "redirect_uri" in manual[0].title and manual[0].manual_steps


def test_https_to_http_downgrade():
    from probegoblin.core.models import Hop

    page = make_page(f"{TARGET}old", source="known_path")
    page.chain.insert(
        0,
        Hop(url=f"{TARGET}old", status=301, headers=[("Location", "http://app.example.com/new")]),
    )
    ctx = make_ctx([make_page(TARGET, source="landing"), page])
    findings = RedirectGoblin()._downgrades(ctx)
    assert findings and findings[0].status == Status.ISSUE


# HostGoblin


@respx.mock
def test_host_reflection_is_manual_check():
    def respond(request):
        host = request.headers.get("x-forwarded-host") or request.headers["host"]
        return respx.MockResponse(
            200, html=f'<link rel="canonical" href="https://{host}/"><p>hello</p>'
        )

    respx.get(TARGET).mock(side_effect=respond)
    result = run(HostGoblin().run(make_ctx([make_page(TARGET, source="landing")])))
    manual = [f for f in result.findings if f.status == Status.MANUAL_CHECK]
    assert len(manual) == 2
    assert "canonical tag" in manual[0].observed
    assert "probegoblin.invalid" in manual[0].reproduce[0]
    hosts = [c.request.headers["host"] for c in respx.calls]
    assert hosts[0] == "probegoblin.invalid" and hosts[1] == "app.example.com"


@respx.mock
def test_host_not_reflected():
    respx.get(TARGET).respond(421)
    result = run(HostGoblin().run(make_ctx([make_page(TARGET, source="landing")])))
    assert titles(result, Status.MANUAL_CHECK) == set()


# DisclosureGoblin


def disclosure_ctx(baseline_status=404, tech=()):
    from probegoblin.core.context import Technology

    landing = make_page(TARGET, body="<title>Home</title>", source="landing")
    base = make_page(f"{TARGET}pg-abc", status=baseline_status, body="nope", source="baseline")
    dot = make_page(f"{TARGET}.pg-abc", status=baseline_status, body="nope", source="baseline")
    ctx = make_ctx([landing])
    ctx.store.baselines = [base, dot]
    ctx.tech = [Technology(name=t) for t in tech]
    return ctx


@respx.mock
def test_disclosure_confirms_content():
    respx.get(f"{TARGET}.git/HEAD").respond(200, text="ref: refs/heads/main\n")
    respx.get(f"{TARGET}.env").respond(
        200,
        text=f"APP_KEY=base64:abc\nAWS_ACCESS_KEY_ID={AWS}\n",
        headers={"Content-Type": "text/plain"},
    )
    respx.get(f"{TARGET}.well-known/security.txt").respond(
        200,
        text="Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00Z\n",
        headers={"Content-Type": "text/plain"},
    )
    respx.get(f"{TARGET}wp-json/wp/v2/users").respond(200, json=[{"id": 1, "slug": "admin"}])
    respx.head(f"{TARGET}actuator/heapdump").respond(404)
    respx.route(host="app.example.com").respond(404, text="nope")
    ctx = disclosure_ctx(tech=["WordPress"])
    result = run(DisclosureGoblin().run(ctx))
    issues = titles(result, Status.ISSUE)
    assert {
        "Git repository exposed",
        ".env file exposed",
        "WordPress users listed by the REST API",
    } <= issues
    env = [f for f in result.findings if f.title == ".env file exposed"][0]
    assert AWS not in env.observed and "IOSFODNN" not in env.observed
    assert "security.txt" in titles(result, Status.OK)
    assert not any(c.request.url.path.startswith("/actuator") for c in respx.calls)


@respx.mock
def test_disclosure_soft_404_catch_all_reports_nothing():
    page = "<html><title>Shop</title>Welcome</html>"
    respx.route(host="app.example.com").respond(200, html=page)
    ctx = disclosure_ctx(baseline_status=200)
    for base in ctx.store.baselines:
        base.body = page.encode()
        base.headers = [("Content-Type", "text/html")]
    result = run(DisclosureGoblin().run(ctx))
    assert titles(result, Status.ISSUE) == set()
    assert titles(result, Status.MANUAL_CHECK) == set()


@respx.mock
def test_disclosure_reads_only_4kb():
    respx.get(f"{TARGET}backup.zip").respond(200, content=b"PK\x03\x04" + b"x" * 100000)
    respx.route(host="app.example.com").respond(404)
    result = run(DisclosureGoblin().run(disclosure_ctx()))
    assert "Backup archive downloadable" in titles(result, Status.ISSUE)
    hit = [f for f in result.findings if f.title == "Backup archive downloadable"][0]
    assert "4096 bytes read" in hit.observed


@respx.mock
def test_heapdump_is_head_only():
    respx.head(f"{TARGET}actuator/heapdump").respond(
        200, headers={"Content-Type": "application/octet-stream", "Content-Length": "123456789"}
    )
    respx.route(host="app.example.com").respond(404)
    result = run(DisclosureGoblin().run(disclosure_ctx(tech=["Spring"])))
    assert "Spring Boot heap dump downloadable" in titles(result, Status.ISSUE)
    heap = [c for c in respx.calls if c.request.url.path == "/actuator/heapdump"]
    assert [c.request.method for c in heap] == ["HEAD"]


@respx.mock
def test_error_pages_and_listings_in_store():
    respx.route(host="app.example.com").respond(404)
    ctx = disclosure_ctx()
    ctx.store.pages[f"{TARGET}files/"] = make_page(
        f"{TARGET}files/", body="<title>Index of /files</title><a>Parent Directory</a>"
    )
    ctx.store.pages[f"{TARGET}err"] = make_page(
        f"{TARGET}err", status=500, body="Traceback (most recent call last):\n  File x"
    )
    result = run(DisclosureGoblin().run(ctx))
    assert {"Directory listing enabled", "Python traceback"} <= titles(result, Status.ISSUE)


@respx.mock
def test_source_map_confirmed_with_1kb_get():
    respx.get(f"{TARGET}app.js.map").respond(
        200, json={"version": 3, "sources": ["webpack:///src/a.js"], "mappings": "AAAA"}
    )
    respx.route(host="app.example.com").respond(404)
    ctx = disclosure_ctx()
    ctx.store.source_maps = [f"{TARGET}app.js.map", "https://cdn.example.net/x.map"]
    result = run(DisclosureGoblin().run(ctx))
    assert "JavaScript source map publicly accessible" in titles(result, Status.ISSUE)
    assert not any(c.request.url.host == "cdn.example.net" for c in respx.calls)


def test_security_txt_parse():
    fields = parse_security_txt("# c\nContact: mailto:a@b\nExpires: 2020-01-01T00:00:00Z\n")
    assert fields["contact"] == ["mailto:a@b"]


# RobotsGoblin


def test_robots_interesting_and_offhost():
    robots = make_page(
        f"{TARGET}robots.txt", headers=[("Content-Type", "text/plain")], body="x", source="robots"
    )
    ctx = make_ctx([make_page(TARGET, source="landing"), robots])
    ctx.store.robots = robots
    ctx.store.robots_entries = ["Disallow: /admin/", "Disallow: /images/", "Sitemap: /s.xml"]
    ctx.store.offhost_urls = ["https://other.example.org/x"]
    result = run(RobotsGoblin().run(ctx))
    hit = [f for f in result.findings if f.title == "Interesting robots.txt entries"][0]
    assert "/admin/" in hit.observed and "/images/" not in hit.observed
    assert "Off-host URLs in robots.txt or sitemaps (not requested)" in titles(
        result, Status.OBSERVATION
    )


# APIGoblin


@respx.mock
def test_api_openapi_and_graphql_introspection():
    spec = {
        "openapi": "3.0.1",
        "info": {"title": "Shop", "version": "1.2"},
        "paths": {"/a": {"get": {}}},
    }
    landing = make_page(TARGET, source="landing")
    docs = make_page(
        f"{TARGET}v3/api-docs",
        headers=[("Content-Type", "application/json")],
        body=json.dumps(spec),
    )
    graphql = make_page(f"{TARGET}graphql", status=400, body='{"errors":[{"message":"no query"}]}')
    respx.get(url__startswith=f"{TARGET}graphql?query=").respond(
        200, json={"data": {"__schema": {"queryType": {"name": "Query"}}}}
    )
    result = run(APIGoblin().run(make_ctx([landing, docs, graphql])))
    assert "API specification reachable without authentication" in titles(
        result, Status.OBSERVATION
    )
    assert "GraphQL introspection enabled" in titles(result, Status.ISSUE)
    assert [c.request.method for c in respx.calls] == ["GET"]


@respx.mock
def test_graphql_rejecting_get_is_not_assessed():
    landing = make_page(TARGET, source="landing")
    graphql = make_page(f"{TARGET}graphql", status=405, body="Only POST is allowed")
    respx.get(url__startswith=f"{TARGET}graphql?query=").respond(
        405, text="GET not supported, use POST"
    )
    result = run(APIGoblin().run(make_ctx([landing, graphql])))
    na = [f for f in result.findings if f.status == Status.NOT_ASSESSED]
    assert na and "rejects GET" in na[0].observed


def test_verbose_api_error():
    landing = make_page(TARGET, source="landing")
    api = make_page(
        f"{TARGET}api",
        status=500,
        headers=[("Content-Type", "application/json")],
        body='{"error":"x","stackTrace":"at Foo.bar"}',
    )
    result = run(APIGoblin().run(make_ctx([landing, api])))
    assert "Verbose API error body" in titles(result, Status.ISSUE)


# LeakGoblin and secrets


def test_secret_patterns_and_redaction():
    text = (
        f"key='{AWS}'\nmaps='AIza{'B' * 35}'\npk='pk_live_{'a' * 24}'\n"
        "password = \"changeme123\"\napi_key: 'realLooking1234567'"
    )
    hits = {h.kind: h for h in find_secrets(text)}
    assert hits["AWS access key ID"].status == Status.ISSUE
    assert hits["Google API key"].status == Status.MANUAL_CHECK
    assert hits["Stripe publishable key"].status == Status.MANUAL_CHECK
    assert hits["Generic secret assignment"].value == "realLooking1234567"
    assert mask(AWS) == "AKIA...(20 chars)"
    assert AWS not in redact_text(text)


def test_leaks_from_js():
    landing = make_page(TARGET, source="landing")
    js = make_page(
        f"{TARGET}app.js",
        headers=[("Content-Type", "application/javascript")],
        body=(
            f"var k='{AWS}';var b='acme-prod.s3.amazonaws.com';var u='http://10.1.2.3:8080/x';"
            "var h='db01.corp.internal';fetch('/api/v2/orders');var m='ops@acme-corp.co.uk';"
        ),
        source="js",
    )
    ctx = make_ctx([landing, js])
    ctx.store.js = [js]
    result = run(LeakGoblin().run(ctx))
    aws = [f for f in result.findings if f.title == "AWS access key ID in JavaScript"][0]
    assert aws.status == Status.ISSUE and AWS not in aws.observed and "AKIA..." in aws.observed
    assert AWS not in aws.reproduce[0]
    observations = titles(result, Status.OBSERVATION)
    assert {
        "Cloud storage references",
        "Internal hostnames or private addresses",
        "Email addresses",
    } <= observations
    assert result.tables and ["/api/v2/orders", f"{TARGET}app.js line 1"] in result.tables[0].rows


def test_leaks_clean_page_has_nothing():
    landing = make_page(
        TARGET, body="<title>Home</title><p>Welcome to the shop</p>", source="landing"
    )
    result = run(LeakGoblin().run(make_ctx([landing])))
    assert [f.status for f in result.findings] == [Status.OK]

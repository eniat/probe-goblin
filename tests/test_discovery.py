from __future__ import annotations

import respx

from probegoblin.core.discovery import Discovery, tag_page
from probegoblin.core.htmlparse import parse_html
from probegoblin.core.http_client import SafeClient, Scope
from tests.conftest import fast_settings, make_page, run

TARGET = "https://app.example.com/"
LANDING = """<html><head><title>Home</title><link rel="icon" href="/static/icon.png">
<link rel="modulepreload" href="/static/mod.js"></head><body>
<script src="/static/app.js"></script>
<script src="https://cdn.example.net/lib.js" integrity="sha384-x"></script>
<script>var a = 1;
//# sourceMappingURL=/static/inline.map</script>
<a href="/search?q=x&next=/home">s</a></body></html>"""


def discover(settings=None):
    settings = settings or fast_settings()

    async def go():
        async with SafeClient(settings, Scope.from_url(TARGET)) as client:
            return await Discovery(client, settings, TARGET).run()

    return run(go())


@respx.mock
def test_page_store_build():
    respx.get(TARGET).respond(200, html=LANDING)
    respx.get(f"{TARGET}robots.txt").respond(
        200,
        text="User-agent: *\nDisallow: /admin/\nDisallow: /logout\nDisallow: /*.php$\n"
        "Sitemap: https://app.example.com/sitemap-pages.xml\n",
        headers={"Content-Type": "text/plain"},
    )
    respx.get(f"{TARGET}sitemap-pages.xml").respond(
        200,
        text="<urlset><url><loc>https://app.example.com/about</loc></url>"
        "<url><loc>https://other.example.org/x</loc></url></urlset>",
        headers={"Content-Type": "application/xml"},
    )
    respx.get(f"{TARGET}login").respond(
        200, html="<html><title>Welcome</title><form><input type=password></form></html>"
    )
    respx.get(f"{TARGET}static/app.js").respond(
        200,
        text="x()\n//# sourceMappingURL=app.js.map",
        headers={"Content-Type": "text/javascript"},
    )
    respx.get(f"{TARGET}static/icon.png").respond(
        200, content=b"\x89PNG", headers={"Content-Type": "image/png"}
    )
    other = respx.route(host="other.example.org").respond(200)
    cdn = respx.route(host="cdn.example.net").respond(200)
    logout = respx.get(f"{TARGET}logout").respond(200)
    respx.route(host="app.example.com").respond(404, html="<title>Not found</title>")

    store = discover()
    assert store.landing.ok and "landing" in store.landing.tags
    assert store.pages[f"{TARGET}login"].tags == {"login"}
    assert f"{TARGET}about" in store.pages
    assert f"{TARGET}admin/" in store.pages
    assert "https://other.example.org/x" in store.offhost_urls
    assert f"{TARGET}logout" in store.skipped
    assert not logout.called and not other.called and not cdn.called
    assert [p.url for p in store.js] == [f"{TARGET}static/app.js"]
    assert (
        "https://app.example.com/",
        "https://cdn.example.net/lib.js",
    ) in store.third_party_scripts
    assert store.favicon is not None and store.favicon.url.endswith("icon.png")
    assert f"{TARGET}static/app.js.map" in store.source_maps
    assert f"{TARGET}static/inline.map" in store.source_maps
    assert (TARGET, "https://app.example.com/search?q=x&next=/home", "next") in store.url_params
    assert len(store.baselines) == 3


@respx.mock
def test_soft_404_catch_all():
    page = "<html><title>Shop</title><body>Welcome to the shop</body></html>"
    respx.route(host="app.example.com").respond(200, html=page)
    store = discover()
    assert store.landing.ok
    assert store.pages[f"{TARGET}login"].soft_404
    assert store.pages[f"{TARGET}swagger.json"].soft_404
    assert not store.tagged("login")


@respx.mock
def test_soft_404_reflecting_path_is_caught():
    def respond(request):
        if request.url.path == "/":
            return respx.MockResponse(200, html="<title>Home</title>real landing page")
        return respx.MockResponse(
            200, html=f"<title>Oops</title>Sorry, {request.url.path} was not found"
        )

    respx.route(host="app.example.com").mock(side_effect=respond)
    store = discover()
    assert store.pages[f"{TARGET}login"].soft_404
    assert store.landing.ok


@respx.mock
def test_real_page_not_mistaken_for_soft_404():
    def respond(request):
        if request.url.path == "/login":
            return respx.MockResponse(
                200, html="<title>Shop</title><form><input type=password name=pw></form>"
            )
        return respx.MockResponse(404, html="<title>Shop</title>Not found")

    respx.route(host="app.example.com").mock(side_effect=respond)
    store = discover()
    assert store.pages[f"{TARGET}login"].ok


@respx.mock
def test_js_file_limit():
    scripts = "".join(f'<script src="/js/{n}.js"></script>' for n in range(50))
    respx.get(TARGET).respond(200, html=f"<html>{scripts}</html>")
    js = respx.route(path__regex=r"^/js/").respond(
        200, text="x", headers={"Content-Type": "text/javascript"}
    )
    respx.route(host="app.example.com").respond(404)
    store = discover(fast_settings(max_js_files=7))
    assert js.call_count == 7
    assert len(store.js) == 7


@respx.mock
def test_request_cap_stops_discovery_cleanly():
    respx.route(host="app.example.com").respond(404)
    store = discover(fast_settings(max_requests=5))
    assert store.limit_reason == "request cap reached"
    assert len(respx.calls) == 5


@respx.mock
def test_unreachable_landing():
    import httpx

    respx.route().mock(side_effect=httpx.ConnectError("refused"))
    store = discover()
    assert store.landing.status is None
    assert "ConnectError" in store.landing.error
    assert len(respx.calls) == 1


def test_tagging():
    def tags(url, html="", ctype="text/html"):
        page = make_page(url, headers=[("Content-Type", ctype)], body=html)
        return tag_page(page, parse_html(html) if html else None)

    assert tags(f"{TARGET}account/login") == {"login"}
    assert tags(f"{TARGET}forgot-password") == {"password_reset"}
    assert tags(f"{TARGET}password/reset") == {"password_reset"}
    assert tags(f"{TARGET}my-account") == {"account"}
    assert tags(f"{TARGET}x", "<title>Sign in</title>") == {"login"}
    assert tags(f"{TARGET}v3/api-docs", ctype="application/json") == {"api_docs"}
    assert tags(f"{TARGET}app.js", ctype="application/javascript") == {"static"}
    assert tags(f"{TARGET}about", "<title>About us</title>") == {"other"}

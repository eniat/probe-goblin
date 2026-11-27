from __future__ import annotations

import http.server
import json
import threading

import httpx
import pytest
import respx

from probegoblin.core import browser, jsruntime
from probegoblin.core.browser import BrowserData, BrowserPage, FrameResult, Script, to_set_cookie
from probegoblin.core.context import Technology
from probegoblin.core.models import Status
from probegoblin.core.update import OWN_FILES, Updater
from probegoblin.modules import _retire
from probegoblin.modules.clickjack import ClickjackGoblin
from probegoblin.modules.javascript import JSGoblin
from probegoblin.modules.technology import TechnologyGoblin
from tests.conftest import FIXTURES, TARGET, fast_settings, make_ctx, make_page, run

INTEL = FIXTURES / "intel"
JS = FIXTURES / "js"


def load(name):
    return json.loads((INTEL / name).read_text())


def titles(result, status):
    return {f.title for f in result.findings if f.status == status}


# Runtime expressions


def test_bundled_library_list():
    libs = jsruntime.libraries()
    assert len(libs) >= 150
    names = {lib.name for lib in libs}
    for required in (
        "jQuery",
        "jQuery UI",
        "Bootstrap",
        "React",
        "Angular",
        "AngularJS",
        "Vue.js",
        "Lodash",
        "Underscore.js",
        "Moment.js",
        "Axios",
        "Handlebars",
        "Backbone.js",
        "Knockout.js",
        "Modernizr",
        "DataTables",
        "Chart.js",
        "Three.js",
        "D3.js",
        "Socket.IO",
        "Next.js",
        "Nuxt.js",
    ):
        assert required in names, required
    assert sum(1 for lib in libs if lib.verified) >= 120


@pytest.mark.parametrize("bad", ["alert(1)", "a.b()", "x = 1", "fetch('/')", "a;b", "a.b`x`"])
def test_expressions_must_be_property_reads(bad):
    with pytest.raises(jsruntime.ExpressionError):
        jsruntime.parse_expression(bad)


def test_expression_forms():
    assert jsruntime.parse_expression("window['__core-js_shared__']?.versions?.[0]?.version") == [
        {"path": ["__core-js_shared__", "versions", 0, "version"]}
    ]
    angular = jsruntime.parse_expression(
        "document.querySelector('[ng-version]')?.getAttribute('ng-version')"
    )
    assert angular == [{"selector": "[ng-version]", "attribute": "ng-version"}]


def test_normalise_template_and_strip():
    libs = {lib.name: lib for lib in jsruntime.libraries()}
    assert libs["Three.js"].normalise("149") == "0.149.0"
    assert libs["ReactDOM"].normalise("18.3.1-next-f1338f8080-20240426") == "18.3.1"


# RetireJS static detection


def test_retire_cdn_url_banner_and_filename():
    hits = _retire.scan_url("https://code.jquery.com/1.12.4/jquery.min.js")
    assert any(h.npm == "jquery" and h.version == "1.12.4" and h.method == "CDN URL" for h in hits)
    named = _retire.scan_url("https://app.example.com/js/jquery-1.12.4.min.js")
    assert any(h.method == "filename" for h in named)
    text = (JS / "fake_jquery.js").read_text()
    banner = _retire.scan_content("https://app.example.com/a.js", text)
    assert any(h.version == "1.12.4" and h.method == "version banner" for h in banner)


# JSGoblin


def intel_routes():
    respx.post("https://api.osv.dev/v1/querybatch").respond(
        json={"results": [{"vulns": [{"id": "GHSA-gxr4-xjj5-5px2"}]}, {}]}
    )
    respx.get("https://api.osv.dev/v1/vulns/GHSA-gxr4-xjj5-5px2").respond(
        json=load("osv_GHSA-gxr4-xjj5-5px2.json")
    )
    respx.get("https://registry.npmjs.org/jquery").respond(json=load("npm_jquery.json"))
    respx.get(url__startswith="https://registry.npmjs.org/").respond(
        json={"dist-tags": {"latest": "4.17.21"}, "time": {"4.17.21": "2021-02-20T00:00:00Z"}}
    )
    respx.get("https://endoflife.date/api/v1/products/jquery").respond(json=load("eol_jquery.json"))
    respx.get(url__startswith="https://api.first.org/").respond(json=load("epss.json"))
    respx.get(url__startswith="https://www.cisa.gov/").respond(json=load("kev.json"))


@respx.mock
def test_jsgoblin_runtime_static_and_intel():
    intel_routes()
    jquery_js = make_page(
        f"{TARGET}static/jquery-1.12.4.min.js",
        headers=[("Content-Type", "application/javascript")],
        body=(JS / "fake_jquery.js").read_text(),
        source="js",
    )
    ctx = make_ctx([make_page(TARGET, source="landing"), jquery_js])
    ctx.store.js = [jquery_js]
    ctx.browser = BrowserData(
        pages=[
            BrowserPage(
                url=TARGET,
                final_url=TARGET,
                status=200,
                runtime={
                    "jQuery": {"version": "1.12.4", "expression": "jQuery.fn.jquery"},
                    "Lodash": {"version": "4.17.15", "expression": "_.VERSION"},
                    "Select2": {"version": None, "expression": None},
                },
            )
        ]
    )
    result = run(JSGoblin().run(ctx))
    table = {row[0]: row for row in result.tables[0].rows}
    assert table["jQuery"][1] == "1.12.4"
    assert table["jQuery"][2] == "runtime, version banner"
    assert table["jQuery"][4].startswith("EOL")
    assert "Outdated" in table["jQuery"][6] and "Known vulnerability" in table["jQuery"][6]
    assert table["Lodash"][2] == "runtime"
    assert table["Select2"][1] == "Unknown"
    issue = [f for f in result.findings if f.title == "jQuery 1.12.4 has known vulnerabilities"][0]
    assert "CVE-2020-11022" in issue.observed and "fixed in 3.5.0" in issue.observed
    assert "EPSS 0.992" in issue.observed
    unknown = [f for f in result.findings if f.title == "Select2: version unknown"][0]
    assert "CVE check not possible: version unknown" in unknown.why_it_matters


@respx.mock
def test_filename_alone_never_gives_a_version():
    intel_routes()
    plain = make_page(
        f"{TARGET}js/jquery-1.12.4.min.js",
        headers=[("Content-Type", "application/javascript")],
        body="var x = 1;",
        source="js",
    )
    ctx = make_ctx([make_page(TARGET, source="landing"), plain])
    ctx.store.js = [plain]
    result = run(JSGoblin().run(ctx))
    row = [r for r in result.tables[0].rows if r[0] == "jQuery"][0]
    assert row[1] == "Unknown" and "filename suggests 1.12.4" in row[2]
    assert not titles(result, Status.ISSUE)


def test_jsgoblin_without_browser_reports_runtime_not_assessed():
    ctx = make_ctx([make_page(TARGET, source="landing")])
    ctx.browser_reason = "Chromium not installed (probegoblin setup)"
    result = run(JSGoblin().run(ctx))
    na = [f for f in result.findings if f.title == "Runtime library detection"]
    assert na and "Chromium not installed" in na[0].observed


def test_sri_missing_on_third_party_scripts():
    body = (
        '<script src="https://cdn.example.net/a.js"></script>'
        '<script src="https://cdn.example.net/b.js" integrity="sha384-x"></script>'
        '<script src="/local.js"></script>'
    )
    ctx = make_ctx([make_page(TARGET, body=body, source="landing")])
    findings = JSGoblin()._sri(ctx)
    assert findings and findings[0].observed == "https://cdn.example.net/a.js"


# Cookies and frames from the browser


def test_browser_cookie_samesite_lax_is_not_trusted():
    cookie = to_set_cookie(
        {"name": "t", "value": "abc", "domain": "app.example.com", "path": "/", "sameSite": "Lax"},
        TARGET,
    )
    assert cookie.samesite is None and cookie.from_browser
    strict = to_set_cookie({"name": "t", "domain": "a", "sameSite": "Strict"}, TARGET)
    assert strict.samesite == "Strict"


def test_clickjack_uses_frame_results():
    ctx = make_ctx([make_page(TARGET, source="landing")])
    ctx.browser = BrowserData(
        frames=[FrameResult(TARGET, "framed", "page rendered inside the frame")]
    )
    result = run(ClickjackGoblin().run(ctx))
    assert "Framing confirmed in Chromium" in titles(result, Status.ISSUE)


# TechnologyGoblin and NVD


def tech_ctx():
    landing = make_page(TARGET, headers=[("Server", "nginx/1.18.0")], source="landing")
    return make_ctx([landing])


def test_nvd_not_assessed_without_key(monkeypatch):
    from probegoblin.modules import technology

    monkeypatch.setattr(technology, "find_tool", lambda name: None)
    result = run(TechnologyGoblin().run(tech_ctx()))
    na = [f for f in result.findings if f.title == "CVE lookup for server-side versions"]
    assert na and "NVD_API_KEY not set" in na[0].observed


@respx.mock
def test_nvd_results_are_labelled_unconfirmed(monkeypatch):
    from probegoblin.modules import technology

    monkeypatch.setattr(technology, "find_tool", lambda name: None)
    monkeypatch.setenv("NVD_API_KEY", "test-key")
    route = respx.get(url__startswith="https://services.nvd.nist.gov/").respond(
        json=load("nvd_nginx.json")
    )
    result = run(TechnologyGoblin().run(tech_ctx()))
    hit = [f for f in result.findings if f.title.startswith("Nginx 1.18.0:")][0]
    assert hit.status == Status.MANUAL_CHECK
    assert "Version-based, unconfirmed, distro backports possible" in hit.why_it_matters
    assert route.calls.last.request.headers["apikey"] == "test-key"


def test_js_and_dom_fingerprints_from_browser(monkeypatch):
    from probegoblin.modules import technology

    monkeypatch.setattr(technology, "find_tool", lambda name: None)
    ctx = make_ctx([make_page(TARGET, source="landing")])
    ctx.browser = BrowserData(
        pages=[BrowserPage(url=TARGET, js_properties={"jQuery.fn.jquery": "3.6.0"})]
    )
    run(TechnologyGoblin().run(ctx))
    assert any(t.name == "jQuery" and t.version == "3.6.0" for t in ctx.tech)


# update


def updater(tmp_path, transport):
    return Updater(client=httpx.Client(transport=transport), root=tmp_path / "data")


def test_update_replaces_only_valid_files(tmp_path):
    good_retire = (
        FIXTURES.parent.parent / "probegoblin/data/retirejs/jsrepository.json"
    ).read_text()

    def handler(request):
        url = str(request.url)
        if url.endswith("jsrepository.json"):
            return httpx.Response(200, text=good_retire)
        if "webappanalyzer" in url:
            return httpx.Response(200, text="not json")
        return httpx.Response(404)

    results = updater(tmp_path, httpx.MockTransport(handler)).run()
    by_name = {r.name: r for r in results}
    assert by_name["RetireJS repository"].ok
    assert not by_name["webappanalyzer fingerprints"].ok
    assert not (tmp_path / "data" / "webappanalyzer").exists()
    for name in OWN_FILES:
        assert not by_name[name].ok and not (tmp_path / "data" / name).exists()


def test_update_rejects_invalid_runtime_file(tmp_path):
    bad = 'libraries:\n- {name: Evil, npm: x, version: ["alert(1)"]}\n'

    def handler(request):
        if str(request.url).endswith("js_runtime.yaml"):
            return httpx.Response(200, text=bad)
        return httpx.Response(500)

    result = updater(tmp_path, httpx.MockTransport(handler)).own("js_runtime.yaml")
    assert not result.ok and not (tmp_path / "data" / "js_runtime.yaml").exists()


def test_data_falls_back_to_bundled(tmp_path, monkeypatch):
    from probegoblin.core import datafiles

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert datafiles.origin("favicons.toml") == "bundled"
    (tmp_path / "probegoblin").mkdir()
    (tmp_path / "probegoblin" / "favicons.toml").write_text("[[favicon]]\nhash=1\nproduct='x'\n")
    assert datafiles.origin("favicons.toml") == "updated"


# Live browser stage (skipped without Chromium)


PAGES = {
    "/": (
        "<html><head><title>Shop</title><script src='/static/jquery-1.12.4.min.js'></script>"
        "<script src='/static/bundle.js'></script></head><body><p>Welcome</p>"
        "<script>document.cookie='tracker=abc123; path=/';</script></body></html>",
        [],
    ),
    "/login": (
        "<html><head><title>Log in</title></head><body><form><input type=password></form>"
        "</body></html>",
        [],
    ),
    "/account": (
        "<html><title>Account</title><body><p>Mine</p></body></html>",
        [("X-Frame-Options", "DENY")],
    ),
    "/reset-password": (
        "<html><head><title>Reset password</title><style>body{display:none}</style>"
        "<script>if (self === top) { document.documentElement.className = 'ok'; }"
        " else { top.location = self.location; }</script>"
        "<style>.ok body{display:block}</style></head><body><p>Reset</p></body></html>",
        [],
    ),
}


class Handler(http.server.BaseHTTPRequestHandler):
    seen_headers: list[dict] = []

    def do_GET(self):  # noqa: N802 - http.server API
        Handler.seen_headers.append({"path": self.path, **dict(self.headers)})
        path = self.path.split("?")[0]
        headers = []
        if path == "/static/jquery-1.12.4.min.js":
            body, ctype = (JS / "fake_jquery.js").read_bytes(), "application/javascript"
        elif path == "/static/bundle.js":
            body, ctype = (JS / "renamed_bundle.js").read_bytes(), "application/javascript"
        elif path in PAGES:
            text, headers = PAGES[path]
            body, ctype = text.encode(), "text/html"
        else:
            body, ctype = b"<title>Not found</title>", "text/html"
        self.send_response(200 if path in PAGES or path.startswith("/static/") else 404)
        self.send_header("Content-Type", ctype)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def site():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


needs_browser = pytest.mark.skipif(
    browser.unavailable_reason() is not None, reason="Chromium not installed"
)


@needs_browser
def test_browser_stage_live(site):
    settings = fast_settings(headers={"X-Pentest": "abc"})
    stage = browser.BrowserStage(f"{site}/", settings, frame_test=True)
    urls = [f"{site}/", f"{site}/login", f"{site}/account", f"{site}/reset-password"]
    data = run(stage.run(urls))
    runtime = data.pages[0].runtime
    assert runtime["jQuery"]["version"] == "1.12.4"
    assert runtime["Lodash"]["version"] == "4.17.15"  # renamed bundle, runtime only
    assert any(c.name == "tracker" and c.from_browser for c in data.cookies)
    outcomes = {f.url.removeprefix(site): f.outcome for f in data.frames}
    assert outcomes["/"] == "framed"
    assert outcomes["/login"] == "framed"
    assert outcomes["/account"] == "blocked"
    assert outcomes["/reset-password"] == "broke out"
    assert data.loads <= settings.browser_page_limit
    assert any(s.url.endswith("bundle.js") for s in data.scripts)
    assert all(h.get("X-Pentest") == "abc" for h in Handler.seen_headers if h["path"] == "/")


@needs_browser
def test_browser_never_leaves_the_target(site):
    Handler.seen_headers.clear()
    settings = fast_settings()
    stage = browser.BrowserStage(f"{site}/", settings, frame_test=False)
    data = run(stage.run([f"{site}/"]))
    assert data.loads == 1
    paths = {h["path"] for h in Handler.seen_headers}
    assert paths <= {"/", "/static/jquery-1.12.4.min.js", "/static/bundle.js", "/favicon.ico"}


def test_browser_stage_needs_chromium_message(monkeypatch):
    browser.chromium_status.cache_clear()
    monkeypatch.delenv("PROBEGOBLIN_CHROMIUM", raising=False)
    monkeypatch.setattr(browser, "chromium_path", lambda: None)
    monkeypatch.setattr(
        browser.subprocess,
        "run",
        lambda *a, **k: type("R", (), {"stdout": "Install location: /nonexistent/chromium"})(),
    )
    assert browser.unavailable_reason() == "Chromium not installed (probegoblin setup)"
    browser.chromium_status.cache_clear()


def test_context_technology_type():
    assert Technology(name="x", version="1").label == "x 1"
    assert Script("u", "b", "p").url == "u"

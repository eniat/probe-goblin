from __future__ import annotations

import time

import httpx
import pytest
import respx

from probegoblin.core.http_client import (
    PURPOSE_DIRECT_IP,
    PURPOSE_HTTP_CHECK,
    MethodNotAllowedError,
    OutOfScopeError,
    RequestCapReachedError,
    SafeClient,
    Scope,
    TargetBlockedError,
    parse_retry_after,
)
from tests.conftest import fast_settings, run

TARGET = "https://app.example.com/"


def client(**overrides) -> SafeClient:
    return SafeClient(fast_settings(**overrides), Scope.from_url(TARGET, ["192.0.2.10"]))


@pytest.mark.parametrize(
    "method", ["POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "PROPFIND", "MKCOL", "post"]
)
def test_refuses_methods_other_than_get_head_options(method):
    async def go():
        async with client() as c:
            await c.fetch(TARGET, method)

    with respx.mock(assert_all_called=False) as mock:
        route = mock.route().respond(200)
        with pytest.raises(MethodNotAllowedError):
            run(go())
        assert not route.called


@respx.mock
def test_allows_get_head_options():
    respx.route(host="app.example.com").respond(200, text="hi")

    async def go():
        async with client() as c:
            return [await c.fetch(TARGET, m) for m in ("GET", "HEAD", "OPTIONS")]

    pages = run(go())
    assert [p.status for p in pages] == [200, 200, 200]
    assert pages[1].body == b""


@pytest.mark.parametrize(
    "url",
    [
        "https://other.example.com/",
        "https://www.app.example.com/",
        "http://app.example.com/",
        "https://app.example.com:8443/",
        "https://192.0.2.10/",
    ],
)
def test_same_host_lock(url):
    async def go():
        async with client() as c:
            await c.fetch(url)

    with respx.mock(assert_all_called=False) as mock:
        route = mock.route().respond(200)
        with pytest.raises(OutOfScopeError):
            run(go())
        assert not route.called


def test_narrow_exceptions_to_the_lock():
    scope = Scope.from_url(TARGET, ["192.0.2.10"])
    assert scope.allows(httpx.URL("http://app.example.com/"), PURPOSE_HTTP_CHECK)
    assert not scope.allows(httpx.URL("http://app.example.com/admin"), PURPOSE_HTTP_CHECK)
    assert scope.allows(httpx.URL("https://192.0.2.10/"), PURPOSE_DIRECT_IP)
    assert scope.allows(httpx.URL("http://192.0.2.10/"), PURPOSE_DIRECT_IP)
    assert not scope.allows(httpx.URL("http://192.0.2.99/"), PURPOSE_DIRECT_IP)
    assert not scope.allows(httpx.URL("https://evil.example/"), PURPOSE_DIRECT_IP)


@respx.mock
def test_off_host_redirect_recorded_not_followed():
    respx.get(TARGET).respond(302, headers={"Location": "https://sso.example.net/login"})
    evil = respx.get("https://sso.example.net/login").respond(200)

    async def go():
        async with client() as c:
            return await c.fetch(TARGET)

    page = run(go())
    assert page.status == 302
    assert page.offsite_redirect == "https://sso.example.net/login"
    assert not evil.called


@respx.mock
def test_same_host_redirects_followed_up_to_limit():
    for n in range(10):
        respx.get(f"https://app.example.com/r{n}").respond(302, headers={"Location": f"/r{n + 1}"})

    async def go():
        async with client() as c:
            return await c.fetch("https://app.example.com/r0")

    page = run(go())
    assert len(page.chain) == 6
    assert "more than 5 redirects" in page.error


@respx.mock
def test_redirect_to_www_is_not_followed():
    respx.get(TARGET).respond(301, headers={"Location": "https://www.app.example.com/"})

    async def go():
        async with client() as c:
            return await c.fetch(TARGET)

    page = run(go())
    assert page.offsite_redirect == "https://www.app.example.com/"
    assert len(respx.calls) == 1


@respx.mock
def test_hostname_never_altered():
    respx.route().respond(200)

    async def go():
        async with SafeClient(fast_settings(), Scope.from_url("https://example.com/")) as c:
            await c.fetch("https://example.com/")

    run(go())
    request = respx.calls.last.request
    assert request.url.host == "example.com"
    assert request.headers["host"] == "example.com"


@respx.mock
def test_pinned_ip_keeps_hostname_for_host_header():
    route = respx.route(host="192.0.2.10").respond(200)
    settings = fast_settings(pinned_ip="192.0.2.10")

    async def go():
        async with SafeClient(settings, Scope.from_url(TARGET)) as c:
            return await c.fetch(TARGET)

    page = run(go())
    assert route.called
    request = route.calls.last.request
    assert request.headers["host"] == "app.example.com"
    assert request.extensions.get("sni_hostname") == "app.example.com"
    assert page.url == TARGET


@respx.mock
def test_rate_limiter_spaces_requests():
    respx.route().respond(200)

    async def go():
        async with SafeClient(fast_settings(rate=20, concurrency=5), Scope.from_url(TARGET)) as c:
            start = time.monotonic()
            for n in range(10):
                await c.fetch(f"{TARGET}p{n}")
            return time.monotonic() - start

    assert run(go()) >= 0.4


@respx.mock
def test_request_cap():
    respx.route().respond(200)

    async def go():
        async with client(max_requests=3) as c:
            for n in range(3):
                await c.fetch(f"{TARGET}{n}")
            assert c.sent == 3
            await c.fetch(f"{TARGET}x")

    with pytest.raises(RequestCapReachedError):
        run(go())


@respx.mock
def test_backoff_honours_retry_after(no_sleep):
    route = respx.get(TARGET)
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "7"}),
        httpx.Response(503),
        httpx.Response(200),
    ]

    async def go():
        async with client() as c:
            return await c.fetch(TARGET), c.sent

    page, sent = run(go())
    assert page.status == 200
    assert sent == 3
    assert 7 in no_sleep
    assert 2.0 in no_sleep or 1.0 in no_sleep


def test_parse_retry_after():
    assert parse_retry_after("5") == 5
    assert parse_retry_after("999") == 60
    assert parse_retry_after(None) is None
    assert parse_retry_after("garbage") is None


@respx.mock
def test_repeated_blocking_stops_with_yes(no_sleep):
    respx.route().respond(429)

    async def go():
        async with client(assume_yes=True) as c:
            for n in range(5):
                await c.fetch(f"{TARGET}{n}")
            assert c.stopped
            await c.fetch(f"{TARGET}after")

    with pytest.raises(TargetBlockedError):
        run(go())


@respx.mock
def test_blocking_prompt_can_slow_down(no_sleep):
    respx.route().respond(403)
    asked = []

    async def answer(reason):
        asked.append(reason)
        return "slower"

    async def go():
        settings = fast_settings(rate=10)
        async with SafeClient(settings, Scope.from_url(TARGET), on_blocked=answer) as c:
            c.count_403 = True
            for n in range(5):
                await c.fetch(f"{TARGET}{n}")
            return c.limiter.rate

    assert run(go()) == 5
    assert "403" in asked[0]


@respx.mock
def test_403_not_counted_when_baseline_is_403(no_sleep):
    respx.route().respond(403)

    async def go():
        async with client(assume_yes=True) as c:
            c.count_403 = False
            for n in range(8):
                await c.fetch(f"{TARGET}{n}")
            return c.stopped

    assert run(go()) is False


@respx.mock
def test_response_size_limit():
    respx.get(TARGET).respond(200, content=b"a" * 5000)

    async def go():
        async with client() as c:
            return await c.fetch(TARGET, max_bytes=1000)

    page = run(go())
    assert len(page.body) == 1000
    assert page.truncated


@respx.mock
def test_server_cookies_are_not_replayed():
    respx.get(f"{TARGET}a").respond(200, headers={"Set-Cookie": "sid=abc; Path=/"})
    respx.get(f"{TARGET}b").respond(200)

    async def go():
        async with client() as c:
            await c.fetch(f"{TARGET}a")
            await c.fetch(f"{TARGET}b")

    run(go())
    assert "cookie" not in respx.calls.last.request.headers


@respx.mock
def test_supplied_cookie_and_headers_sent():
    respx.route().respond(200)

    async def go():
        settings = fast_settings(cookie="session=s3cr3t", headers={"X-Pentest": "abc"})
        async with SafeClient(settings, Scope.from_url(TARGET)) as c:
            await c.fetch(TARGET)

    run(go())
    request = respx.calls.last.request
    assert request.headers["cookie"] == "session=s3cr3t"
    assert request.headers["x-pentest"] == "abc"
    assert request.headers["user-agent"].startswith("ProbeGoblin/")


@respx.mock
def test_timeout_is_reported_not_raised():
    respx.get(TARGET).mock(side_effect=httpx.ConnectTimeout("slow"))

    async def go():
        async with client() as c:
            return await c.fetch(TARGET)

    page = run(go())
    assert page.status is None
    assert "timed out" in page.error


@respx.mock
def test_request_log(tmp_path):
    respx.route().respond(204)
    log = tmp_path / "requests.log"

    async def go():
        with log.open("w") as handle:
            settings = fast_settings()
            async with SafeClient(settings, Scope.from_url(TARGET), request_log=handle) as c:
                await c.fetch(TARGET, "HEAD", module="HeaderGoblin")

    run(go())
    line = log.read_text().strip()
    assert line.endswith(f"HEAD {TARGET} 204 HeaderGoblin")
    assert line[:4].isdigit() and line[19] == "Z"

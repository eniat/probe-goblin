"""The only HTTP client modules may use for target traffic.

Enforced here, so no module can bypass it:
- GET, HEAD and OPTIONS only
- same-host lock (target scheme, host and port), with two narrow exceptions
- one shared rate limiter, concurrency limit and request cap
- same-host redirects followed up to the limit, other redirects recorded only
- backoff on 429 and 503, pause when the target keeps blocking
"""

from __future__ import annotations

import asyncio
import http.cookiejar
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import IO

import httpx

from probegoblin.core.config import Settings
from probegoblin.core.models import Hop, Page

ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
BACKOFF_CODES = frozenset({429, 503})
MAX_RETRIES = 3
MAX_RETRY_AFTER = 60.0

# Purposes that unlock the two exceptions to the same-host lock.
PURPOSE_HTTP_CHECK = "http_check"
PURPOSE_DIRECT_IP = "direct_ip"


class MethodNotAllowedError(Exception):
    """Raised for any method other than GET, HEAD or OPTIONS."""


class OutOfScopeError(Exception):
    """Raised for a URL outside the same-host lock."""


class RequestCapReachedError(Exception):
    """Raised once the per-target request cap is spent."""


class TargetBlockedError(Exception):
    """Raised after the tester chose to stop because the target kept blocking."""


def default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def url_port(url: httpx.URL) -> int:
    return url.port or default_port(url.scheme)


@dataclass
class Scope:
    scheme: str
    host: str
    port: int
    ips: list[str] = field(default_factory=list)

    @classmethod
    def from_url(cls, url: str, ips: list[str] | None = None) -> Scope:
        parsed = httpx.URL(url)
        return cls(parsed.scheme, parsed.host, url_port(parsed), list(ips or []))

    def is_target(self, url: httpx.URL) -> bool:
        return (url.scheme, url.host, url_port(url)) == (self.scheme, self.host, self.port)

    def allows(self, url: httpx.URL, purpose: str | None = None) -> bool:
        if self.is_target(url):
            return True
        root = url.path in ("", "/") and not url.query
        if purpose == PURPOSE_HTTP_CHECK:
            return url.scheme == "http" and url.host == self.host and url_port(url) == 80 and root
        if purpose == PURPOSE_DIRECT_IP:
            return (
                url.host in self.ips
                and url.scheme in ("http", "https")
                and url_port(url) == default_port(url.scheme)
                and root
            )
        return False


class PinnedTransport(httpx.AsyncHTTPTransport):
    """Connects to a pinned IP while keeping the hostname for Host and SNI."""

    def __init__(self, host: str, ip: str | None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.host = host
        self.ip = ip

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self.ip and request.url.host == self.host:
            request.extensions = {**request.extensions, "sni_hostname": self.host}
            request.url = request.url.copy_with(host=self.ip)
        return await super().handle_async_request(request)


class RateLimiter:
    """Spaces requests evenly at `rate` per second."""

    def __init__(self, rate: float) -> None:
        self.rate = rate
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            start = max(self._next, now)
            self._next = start + 1.0 / self.rate
        delay = start - now
        if delay > 0:
            await asyncio.sleep(delay)


def parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return min(float(value), MAX_RETRY_AFTER)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, min((when - datetime.now(UTC)).total_seconds(), MAX_RETRY_AFTER))


class _RejectAll(http.cookiejar.DefaultCookiePolicy):
    """Never store or send server cookies."""

    def set_ok(self, cookie, request) -> bool:
        return False

    def return_ok(self, cookie, request) -> bool:
        return False


BlockedHandler = Callable[[str], Awaitable[str]]


class SafeClient:
    def __init__(
        self,
        settings: Settings,
        scope: Scope,
        request_log: IO[str] | None = None,
        on_blocked: BlockedHandler | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.scope = scope
        self.request_log = request_log
        self.on_blocked = on_blocked
        self.limiter = RateLimiter(settings.rate)
        self.semaphore = asyncio.Semaphore(settings.concurrency)
        self.sent = 0
        self.blocked_responses = 0
        self.consecutive_blocked = 0
        self.count_403 = False
        self.stopped = False
        self._block_lock = asyncio.Lock()
        headers = {"User-Agent": settings.user_agent, **settings.extra_headers, **settings.headers}
        if settings.cookie:
            headers["Cookie"] = settings.cookie
        # A jar that accepts nothing: every request carries only what the tester supplied.
        jar = http.cookiejar.CookieJar(policy=_RejectAll())
        self._client = httpx.AsyncClient(
            headers=headers,
            cookies=jar,
            timeout=settings.timeout,
            verify=False,
            follow_redirects=False,
            transport=transport or PinnedTransport(scope.host, settings.pinned_ip, verify=False),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> SafeClient:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    @property
    def remaining(self) -> int:
        return max(0, self.settings.max_requests - self.sent)

    def _log(self, method: str, url: str, status: int | str, module: str) -> None:
        if self.request_log is None:
            return
        stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.request_log.write(f"{stamp} {method} {url} {status} {module}\n")
        self.request_log.flush()

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        *,
        module: str = "discovery",
        source: str = "",
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        max_bytes: int | None = None,
        purpose: str | None = None,
        omit_auth: bool = False,
    ) -> Page:
        """Fetch a URL within scope. Network errors are returned on the Page, not raised."""
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise MethodNotAllowedError(f"{method} is not allowed. Only GET, HEAD and OPTIONS.")
        current = httpx.URL(url)
        if not self.scope.allows(current, purpose):
            raise OutOfScopeError(f"{url} is outside the same-host lock")
        limit = max_bytes or self.settings.max_response_bytes
        page = Page(url=url, source=source, method=method)
        visited = {str(current)}
        started = time.monotonic()
        for _hop in range(self.settings.max_redirects + 1):
            response, body, truncated, error = await self._send(
                method, current, module, headers, limit, omit_auth
            )
            if error is not None:
                page.error = error
                break
            hop = Hop(url=str(current), status=response.status_code, headers=_headers(response))
            page.chain.append(hop)
            location = response.headers.get("location")
            if follow_redirects and response.status_code in REDIRECT_CODES and location:
                target = current.join(location)
                same = self.scope.is_target(target) or (
                    purpose == PURPOSE_HTTP_CHECK and self.scope.allows(target, purpose)
                )
                if not same:
                    page.offsite_redirect = str(target)
                    self._finish(page, hop, body, truncated)
                    break
                if str(target) in visited:
                    page.error = f"redirect loop at {target}"
                    self._finish(page, hop, body, truncated)
                    break
                if len(page.chain) > self.settings.max_redirects:
                    page.error = f"more than {self.settings.max_redirects} redirects"
                    self._finish(page, hop, body, truncated)
                    break
                visited.add(str(target))
                if response.status_code == 303 and method != "HEAD":
                    method = "GET"
                current = target
                continue
            self._finish(page, hop, body, truncated)
            break
        page.elapsed = time.monotonic() - started
        return page

    @staticmethod
    def _finish(page: Page, hop: Hop, body: bytes, truncated: bool) -> None:
        page.status = hop.status
        page.final_url = hop.url
        page.headers = hop.headers
        page.body = body
        page.truncated = truncated

    async def _send(
        self,
        method: str,
        url: httpx.URL,
        module: str,
        headers: dict[str, str] | None,
        limit: int,
        omit_auth: bool = False,
    ) -> tuple[httpx.Response | None, bytes, bool, str | None]:
        for attempt in range(MAX_RETRIES + 1):
            if self.stopped:
                raise TargetBlockedError("stopped after repeated blocking responses")
            if self.sent >= self.settings.max_requests:
                raise RequestCapReachedError("request cap reached")
            async with self.semaphore:
                await self.limiter.wait()
                self.sent += 1
                try:
                    response, body, truncated = await self._stream(
                        method, url, headers, limit, omit_auth
                    )
                except httpx.TimeoutException:
                    self._log(method, str(url), "timeout", module)
                    return None, b"", False, f"timed out after {self.settings.timeout:g}s"
                except httpx.HTTPError as exc:
                    self._log(method, str(url), "error", module)
                    return None, b"", False, f"request failed: {type(exc).__name__}"
            self._log(method, str(url), response.status_code, module)
            if response.status_code in BACKOFF_CODES and attempt < MAX_RETRIES:
                delay = parse_retry_after(response.headers.get("retry-after"))
                await asyncio.sleep(delay if delay is not None else float(2**attempt))
                continue
            await self._track_blocking(response.status_code)
            return response, body, truncated, None
        raise AssertionError("unreachable")

    async def _stream(
        self,
        method: str,
        url: httpx.URL,
        headers: dict[str, str] | None,
        limit: int,
        omit_auth: bool = False,
    ) -> tuple[httpx.Response, bytes, bool]:
        request = self._client.build_request(method, url, headers=headers)
        if omit_auth:
            for name in ["cookie", *self.settings.headers]:
                if name in request.headers:
                    del request.headers[name]
        response = await self._client.send(request, stream=True)
        try:
            chunks: list[bytes] = []
            size = 0
            truncated = False
            if method != "HEAD":
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= limit:
                        truncated = size > limit
                        break
            return response, b"".join(chunks)[:limit], truncated
        finally:
            await response.aclose()

    async def _track_blocking(self, status: int) -> None:
        if status in BACKOFF_CODES:
            self.blocked_responses += 1
        blocked = status in BACKOFF_CODES or (status == 403 and self.count_403)
        if not blocked:
            self.consecutive_blocked = 0
            return
        self.consecutive_blocked += 1
        if self.consecutive_blocked < self.settings.blocked_threshold:
            return
        async with self._block_lock:
            if self.consecutive_blocked < self.settings.blocked_threshold or self.stopped:
                return
            reason = f"{self.consecutive_blocked} consecutive {status} responses"
            choice = "stop"
            if not self.settings.assume_yes and self.on_blocked is not None:
                choice = await self.on_blocked(reason)
            self.consecutive_blocked = 0
            if choice == "slower":
                self.limiter.rate = max(0.2, self.limiter.rate / 2)
            elif choice == "stop":
                self.stopped = True


def _headers(response: httpx.Response) -> list[tuple[str, str]]:
    return [(key.decode("latin-1"), value.decode("latin-1")) for key, value in response.headers.raw]

"""Browser stage: loads a few pages in Chromium as a normal visitor would. No clicks, typing,
form submission or scrolling. Only the landing page, up to three login, account or password
reset pages, and local frame-test pages for ClickjackGoblin are opened."""

from __future__ import annotations

import asyncio
import contextlib
import importlib.metadata
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import httpx

from probegoblin import __version__
from probegoblin.core import jsruntime
from probegoblin.core.cookies import SetCookie

NETWORK_IDLE_MS = 15000
FRAME_WAIT_MS = 10000
MAX_SCRIPT_BYTES = 5 * 1024 * 1024
MAX_AUTH_PAGES = 3
CHROMIUM_ENV = "PROBEGOBLIN_CHROMIUM"


@dataclass
class NetResponse:
    url: str
    status: int
    resource_type: str
    page_url: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Script:
    url: str
    body: str
    page_url: str


@dataclass
class ConsoleMessage:
    page_url: str
    type: str
    text: str


@dataclass
class BrowserPage:
    url: str
    final_url: str | None = None
    status: int | None = None
    dom: str = ""
    runtime: dict[str, dict] = field(default_factory=dict)
    js_properties: dict[str, str] = field(default_factory=dict)
    dom_matches: dict[str, dict] = field(default_factory=dict)
    error: str | None = None


@dataclass
class FrameResult:
    url: str
    outcome: str  # "framed", "blocked", "broke out", "error"
    detail: str = ""


@dataclass
class BrowserData:
    pages: list[BrowserPage] = field(default_factory=list)
    responses: list[NetResponse] = field(default_factory=list)
    scripts: list[Script] = field(default_factory=list)
    console: list[ConsoleMessage] = field(default_factory=list)
    cookies: list[SetCookie] = field(default_factory=list)
    frames: list[FrameResult] = field(default_factory=list)
    blocked_navigations: list[str] = field(default_factory=list)
    loads: int = 0


def chromium_path() -> str | None:
    """Explicit Chromium from PROBEGOBLIN_CHROMIUM, if set."""
    value = os.environ.get(CHROMIUM_ENV)
    return value if value and Path(value).exists() else None


@lru_cache(maxsize=1)
def chromium_status() -> tuple[bool, str | None, str]:
    """(usable, Playwright version, detail). Cached: asks Playwright once per run."""
    try:
        version = importlib.metadata.version("playwright")
    except importlib.metadata.PackageNotFoundError:
        return False, None, "Playwright not installed (pipx reinstall probegoblin)"
    explicit = chromium_path()
    if explicit:
        return True, f"playwright {version}", explicit
    try:
        out = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
            capture_output=True,
            text=True,
            timeout=60,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False, f"playwright {version}", "could not query Playwright"
    locations = re.findall(r"Install location:\s*(\S+)", out)
    if locations and Path(locations[0]).exists():
        return True, f"playwright {version}", locations[0]
    return False, f"playwright {version}", "Chromium not installed (probegoblin setup)"


def unavailable_reason() -> str | None:
    usable, _version, detail = chromium_status()
    return None if usable else detail


def _same_host(url: str, host: str, port: int, scheme: str) -> bool:
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, ValueError):
        return False
    port_of = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.host == host and port_of == port and parsed.scheme == scheme


def to_set_cookie(cookie: dict, page_url: str) -> SetCookie:
    attrs: dict[str, str] = {"path": cookie.get("path", "/")}
    domain = cookie.get("domain", "")
    if domain.startswith("."):
        attrs["domain"] = domain
    if cookie.get("secure"):
        attrs["secure"] = ""
    if cookie.get("httpOnly"):
        attrs["httponly"] = ""
    same_site = cookie.get("sameSite")
    # Chromium reports Lax for cookies without the attribute, so Lax here is not proof.
    if same_site in ("Strict", "None"):
        attrs["samesite"] = same_site
    expires = cookie.get("expires", -1)
    if expires and expires > 0:
        attrs["max-age"] = "persistent"
    return SetCookie(
        name=cookie["name"],
        value=cookie.get("value", ""),
        attrs=attrs,
        raw="(from browser)",
        source_url=page_url,
        from_browser=True,
    )


# How the framed document looks: hidden, empty or visibly rendered.
FRAME_STATE = """() => {
  const b = document.body;
  if (!b) return 'empty';
  const s = getComputedStyle(b);
  if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0') return 'hidden';
  const text = (b.innerText || '').trim().length > 0;
  const things = b.querySelector('input,button,select,textarea,img,svg,canvas,video,iframe,a,form');
  return text || things ? 'visible' : 'empty';
}"""


def frame_html(url: str) -> str:
    safe = url.replace('"', "%22")
    return (
        "<!doctype html><html><body style='margin:0'>"
        f'<iframe id="target" src="{safe}" width="1200" height="800"></iframe>'
        "</body></html>"
    )


class BrowserStage:
    def __init__(
        self,
        target: str,
        settings,
        js_chains: list[str] | None = None,
        dom_queries: list[dict] | None = None,
        frame_test: bool = True,
    ) -> None:
        parsed = httpx.URL(target)
        self.target = target
        self.host = parsed.host
        self.scheme = parsed.scheme
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.settings = settings
        self.js_chains = js_chains or []
        self.dom_queries = dom_queries or []
        self.frame_test = frame_test
        self.data = BrowserData()
        self._tasks: list[asyncio.Task] = []

    def _same(self, url: str) -> bool:
        return _same_host(url, self.host, self.port, self.scheme)

    async def run(self, urls: list[str]) -> BrowserData:
        from playwright.async_api import async_playwright

        limit = self.settings.browser_page_limit
        page_urls = urls[: 1 + MAX_AUTH_PAGES]
        args = []
        if self.settings.pinned_ip:
            args.append(f"--host-resolver-rules=MAP {self.host} {self.settings.pinned_ip}")
        async with async_playwright() as p:
            browser = await p.chromium.launch(executable_path=chromium_path(), args=args)
            try:
                probe = await browser.new_page()
                user_agent = await probe.evaluate("navigator.userAgent")
                await probe.close()
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent=f"{user_agent} ProbeGoblin/{__version__}",
                    java_script_enabled=True,
                )
                if self.settings.cookie:
                    await context.add_cookies(self._cookies())
                await context.route("**/*", self._route)
                for url in page_urls:
                    if self.data.loads >= limit:
                        break
                    self.data.pages.append(await self._load(context, url))
                if self._tasks:
                    await asyncio.gather(*self._tasks, return_exceptions=True)
                for cookie in await context.cookies():
                    if self._cookie_for_target(cookie):
                        self.data.cookies.append(to_set_cookie(cookie, page_urls[0]))
                if self.frame_test:
                    for page in self.data.pages:
                        if self.data.loads >= limit or page.status is None:
                            continue
                        self.data.frames.append(
                            await self._frame(context, page.final_url or page.url)
                        )
                await context.close()
            finally:
                await browser.close()
        return self.data

    def _cookies(self) -> list[dict]:
        cookies = []
        for part in (self.settings.cookie or "").split(";"):
            if "=" in part:
                name, value = part.split("=", 1)
                cookies.append(
                    {
                        "name": name.strip(),
                        "value": value.strip(),
                        "domain": self.host,
                        "path": "/",
                        "secure": self.scheme == "https",
                    }
                )
        return cookies

    def _cookie_for_target(self, cookie: dict) -> bool:
        domain = cookie.get("domain", "").lstrip(".").lower()
        host = self.host.lower()
        return host == domain or host.endswith("." + domain)

    async def _route(self, route, request) -> None:
        url = request.url
        top_level = request.is_navigation_request() and request.frame.parent_frame is None
        if top_level and not self._same(url) and not url.startswith(("about:", "data:")):
            self.data.blocked_navigations.append(url)
            await route.abort()
            return
        if self._same(url):
            extra = {**self.settings.extra_headers, **self.settings.headers}
            if extra:
                await route.continue_(headers={**request.headers, **extra})
                return
        await route.continue_()

    async def _load(self, context, url: str) -> BrowserPage:
        result = BrowserPage(url=url)
        page = await context.new_page()
        page.on("response", lambda response: self._on_response(response, url))
        page.on(
            "console",
            lambda msg: self.data.console.append(ConsoleMessage(url, msg.type, msg.text)),
        )
        self.data.loads += 1
        try:
            response = await page.goto(url, wait_until="load", timeout=NETWORK_IDLE_MS)
            result.status = response.status if response else None
            with contextlib.suppress(Exception):
                await page.wait_for_load_state("networkidle", timeout=NETWORK_IDLE_MS)
        except Exception as exc:  # timeouts and navigation errors
            result.error = f"{type(exc).__name__}: {str(exc).splitlines()[0][:160]}"
        try:
            result.final_url = page.url
            result.dom = await page.content()
            libs = [lib.to_page() for lib in jsruntime.libraries()]
            result.runtime = await page.evaluate(jsruntime.EVALUATOR, libs)
            if self.js_chains:
                result.js_properties = await page.evaluate(jsruntime.JS_PROPERTIES, self.js_chains)
            if self.dom_queries:
                result.dom_matches = await page.evaluate(jsruntime.DOM_QUERY, self.dom_queries)
        except Exception as exc:
            result.error = result.error or f"{type(exc).__name__}: {str(exc).splitlines()[0][:160]}"
        await page.close()
        return result

    def _on_response(self, response, page_url: str) -> None:
        request = response.request
        item = NetResponse(
            url=response.url,
            status=response.status,
            resource_type=request.resource_type,
            page_url=page_url,
        )
        self.data.responses.append(item)
        if request.resource_type == "script":
            self._tasks.append(asyncio.ensure_future(self._capture(response, page_url)))

    async def _capture(self, response, page_url: str) -> None:
        try:
            length = int(response.headers.get("content-length", "0") or 0)
            if length > MAX_SCRIPT_BYTES:
                return
            body = await response.body()
        except Exception:
            return
        if len(body) <= MAX_SCRIPT_BYTES:
            self.data.scripts.append(
                Script(response.url, body.decode("utf-8", errors="replace"), page_url)
            )

    async def _frame(self, context, url: str) -> FrameResult:
        page = await context.new_page()
        messages: list[str] = []
        page.on("console", lambda msg: messages.append(msg.text))
        self.data.loads += 1
        try:
            await page.set_content(frame_html(url))
            frame_el = await page.query_selector("#target")
            frame = await frame_el.content_frame() if frame_el else None
            with contextlib.suppress(Exception):
                if frame:
                    await frame.wait_for_load_state("load", timeout=FRAME_WAIT_MS)
            await page.wait_for_timeout(1500)
            if page.url not in ("about:blank", ""):
                return FrameResult(url, "broke out", f"top page navigated to {page.url}")
            refused = [m for m in messages if "Refused to" in m and "frame" in m.lower()]
            frame = await frame_el.content_frame() if frame_el else None
            if refused or frame is None or (frame.url or "").startswith("chrome-error://"):
                detail = refused[0][:200] if refused else "frame shows a browser error page"
                return FrameResult(url, "blocked", detail)
            state = await frame.evaluate(FRAME_STATE)
            attempted = [m for m in messages if "Unsafe attempt to initiate navigation" in m]
            note = "; frame-busting attempt blocked by the browser" if attempted else ""
            if state == "visible":
                return FrameResult(url, "framed", f"page rendered inside the frame{note}")
            return FrameResult(url, "broke out", f"page {state} inside the frame{note}")
        except Exception as exc:
            return FrameResult(
                url, "error", f"{type(exc).__name__}: {str(exc).splitlines()[0][:160]}"
            )
        finally:
            await page.close()

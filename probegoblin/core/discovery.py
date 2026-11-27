"""Builds the page store once per target. No crawling."""

from __future__ import annotations

import asyncio
import difflib
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

import httpx

from probegoblin.core.config import Settings
from probegoblin.core.htmlparse import HtmlInfo, parse_html, source_maps_in
from probegoblin.core.http_client import (
    RequestCapReachedError,
    SafeClient,
    TargetBlockedError,
)
from probegoblin.core.models import Page

STATIC_EXT = re.compile(
    r"\.(js|mjs|css|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|eot|map|mp4|webm|pdf)$", re.I
)
LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
MAX_CHILD_SITEMAPS = 3
COMPARE_BYTES = 16384


def estimate_requests(settings: Settings) -> int:
    """Upper bound of requests the page store can send, before redirects."""
    fixed = 1 + 3 + 2 + len(settings.known_paths) + 1 + MAX_CHILD_SITEMAPS
    return fixed + settings.max_robots_urls + settings.max_js_files


@dataclass
class PageStore:
    target: str
    landing: Page | None = None
    pages: dict[str, Page] = field(default_factory=dict)
    html: dict[str, HtmlInfo] = field(default_factory=dict)
    baselines: list[Page] = field(default_factory=list)
    robots: Page | None = None
    sitemaps: list[Page] = field(default_factory=list)
    robots_entries: list[str] = field(default_factory=list)
    sitemap_entries: list[str] = field(default_factory=list)
    offhost_urls: list[str] = field(default_factory=list)
    favicon: Page | None = None
    js: list[Page] = field(default_factory=list)
    third_party_scripts: list[tuple[str, str]] = field(default_factory=list)  # (page, src)
    url_params: list[tuple[str, str, str]] = field(default_factory=list)  # (page, url, name)
    source_maps: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    limit_reason: str | None = None

    def all_pages(self) -> list[Page]:
        return list(self.pages.values())

    def tagged(self, *tags: str, ok_only: bool = True) -> list[Page]:
        out = [p for p in self.pages.values() if p.tags.intersection(tags)]
        return [p for p in out if p.ok] if ok_only else out

    def html_pages(self) -> list[Page]:
        return [p for p in self.pages.values() if p.ok and p.is_html]

    def sensitive_pages(self) -> list[Page]:
        """Landing page plus login, account and password reset pages that returned 2xx."""
        out = [self.landing] if self.landing and self.landing.status else []
        for page in self.tagged("login", "account", "password_reset"):
            if all(page.final_url != o.final_url for o in out):
                out.append(page)
        return out

    def info(self, page: Page) -> HtmlInfo | None:
        return self.html.get(page.url)

    def is_soft_404(self, page: Page) -> bool:
        if page.status is None or page.status == 404:
            return False
        return any(_matches_baseline(page, base) for base in self.baselines)


def _normalised(page: Page) -> bytes:
    body = page.body[:COMPARE_BYTES]
    path = urlsplit(page.url).path
    if path and path != "/":
        body = body.replace(path.encode(), b"").replace(path.lstrip("/").encode(), b"")
    return body


def _matches_baseline(page: Page, base: Page) -> bool:
    if base.status is None or page.status != base.status:
        return False
    if page.final_url and base.final_url and page.final_url == base.final_url:
        return page.url != base.url
    if _normalised(page) == _normalised(base):
        return True
    page_title = _title(page)
    if page_title != _title(base):
        return False
    a, b = _normalised(page), _normalised(base)
    return difflib.SequenceMatcher(None, a, b, autojunk=False).quick_ratio() > 0.97 and (
        difflib.SequenceMatcher(None, a, b, autojunk=False).ratio() > 0.97
    )


def _title(page: Page) -> str:
    match = re.search(rb"<title[^>]*>(.*?)</title>", page.body[:COMPARE_BYTES], re.I | re.S)
    return b" ".join(match.group(1).split()).decode("utf-8", "replace") if match else ""


def tag_page(page: Page, info: HtmlInfo | None) -> set[str]:
    url = page.final_url or page.url
    path = urlsplit(url).path.lower()
    title = (info.title if info else "").lower()
    tags: set[str] = set()
    if STATIC_EXT.search(path) or page.content_type.startswith(
        ("image/", "font/", "text/css", "application/javascript", "text/javascript")
    ):
        return {"static"}
    reset = re.search(r"forgot|reset|recover", path) or re.search(
        r"(forgot|reset|recover)\w*\s+(your\s+)?password", title
    )
    if reset:
        tags.add("password_reset")
    has_password = bool(info and any(f.has_password for f in info.forms))
    login_path = re.search(r"(^|/)(log-?in|sign-?in|logon|auth/login)(/|$|\.)", path)
    login_title = re.search(r"\b(log ?in|sign ?in)\b", title)
    if not reset and (login_path or login_title or has_password):
        tags.add("login")
    account = re.search(r"(^|/)(account|my-account|profile|register|signup|sign-up)(/|$)", path)
    if account and not tags:
        tags.add("account")
    if re.search(r"swagger|api-docs|openapi|graphi?ql|(^|/)api(/|$)", path):
        tags.add("api_docs")
    return tags or {"other"}


class Discovery:
    def __init__(self, client: SafeClient, settings: Settings, target: str) -> None:
        self.client = client
        self.settings = settings
        self.target = target
        self.base = httpx.URL(target)
        self.store = PageStore(target=target)

    def absolute(self, ref: str, base: str | None = None) -> httpx.URL | None:
        ref = ref.strip()
        if not ref or ref.startswith(("data:", "javascript:", "mailto:", "tel:", "#", "blob:")):
            return None
        try:
            return httpx.URL(base or self.target).join(ref)
        except (httpx.InvalidURL, ValueError):
            return None

    def same_host(self, url: httpx.URL) -> bool:
        return self.client.scope.is_target(url)

    def unsafe(self, url: httpx.URL) -> bool:
        lowered = (url.path + "?" + (url.query.decode() if url.query else "")).lower()
        return any(word in lowered for word in self.settings.unsafe_url_words)

    async def get(self, url: str | httpx.URL, source: str, **kwargs) -> Page | None:
        key = str(url)
        if key in self.store.pages:
            return self.store.pages[key]
        parsed = httpx.URL(key)
        if self.unsafe(parsed):
            self.store.skipped.append(key)
            return None
        page = await self.client.fetch(key, source=source, **kwargs)
        self.store.pages[key] = page
        return page

    async def gather(self, urls: list[tuple[str, str]], **kwargs) -> list[Page | None]:
        return list(await asyncio.gather(*(self.get(u, s, **kwargs) for u, s in urls)))

    async def run(self) -> PageStore:
        try:
            await self._run()
        except RequestCapReachedError:
            self.store.limit_reason = "request cap reached"
        except TargetBlockedError:
            self.store.limit_reason = "stopped: target kept blocking requests"
        self._finalise()
        return self.store

    async def _run(self) -> None:
        store = self.store
        store.landing = await self.get(self.target, "landing")
        if store.landing is None or store.landing.status is None:
            return
        store.landing.tags.add("landing")

        root = self.base.copy_with(path="/", query=None, fragment=None)
        token = secrets.token_hex(6)
        baselines = await self.gather(
            [
                (str(root.join(f"/pg-{token}")), "baseline"),
                (str(root.join(f"/pg-{token}.php")), "baseline"),
                (str(root.join(f"/.pg-{token}")), "baseline"),
            ]
        )
        store.baselines = [p for p in baselines if p and p.status is not None]
        if store.baselines:
            self.client.count_403 = store.baselines[0].status != 403

        robots, sitemap, *_known = await self.gather(
            [
                (str(root.join("/robots.txt")), "robots"),
                (str(root.join("/sitemap.xml")), "sitemap"),
                *[(str(root.join(path)), "known_path") for path in self.settings.known_paths],
            ]
        )
        store.robots = robots
        await self._sitemaps(robots, sitemap)
        await self._robots_urls()
        self._parse_html_pages()
        await self._favicon()
        await self._javascript()

    async def _sitemaps(self, robots: Page | None, sitemap: Page | None) -> None:
        store = self.store
        if robots and robots.ok and not robots.is_html:
            for line in robots.text.splitlines():
                line = line.split("#", 1)[0].strip()
                if ":" not in line:
                    continue
                key, value = (part.strip() for part in line.split(":", 1))
                if key.lower() in ("allow", "disallow", "sitemap") and value:
                    store.robots_entries.append(f"{key.title()}: {value}")
        candidates: list[str] = []
        for entry in store.robots_entries:
            if entry.startswith("Sitemap:"):
                candidates.append(entry.split(":", 1)[1].strip())
        if sitemap and sitemap.ok and not sitemap.is_html:
            store.sitemaps.append(sitemap)
        fetched = 0
        child_urls: list[str] = []
        for page in list(store.sitemaps):
            child_urls.extend(self._sitemap_locs(page, index_only=True))
        for ref in candidates + child_urls:
            url = self.absolute(ref)
            if url is None:
                continue
            if not self.same_host(url):
                store.offhost_urls.append(str(url))
                continue
            if str(url) in store.pages or str(url).endswith(".gz"):
                continue
            if fetched >= MAX_CHILD_SITEMAPS:
                break
            fetched += 1
            page = await self.get(url, "sitemap")
            if page and page.ok and not page.is_html:
                store.sitemaps.append(page)
        for page in store.sitemaps:
            store.sitemap_entries.extend(self._sitemap_locs(page, index_only=False))

    @staticmethod
    def _sitemap_locs(page: Page, index_only: bool) -> list[str]:
        text = page.text
        is_index = "<sitemapindex" in text[:2048].lower()
        if index_only != is_index:
            return []
        return LOC_RE.findall(text)

    async def _robots_urls(self) -> None:
        store = self.store
        picked: list[str] = []
        refs = list(store.sitemap_entries)
        for entry in store.robots_entries:
            key, value = entry.split(":", 1)
            value = value.strip()
            if key in ("Allow", "Disallow") and "*" not in value and "$" not in value:
                refs.append(value)
        for ref in refs:
            url = self.absolute(ref)
            if url is None:
                continue
            if not self.same_host(url):
                if str(url) not in store.offhost_urls:
                    store.offhost_urls.append(str(url))
                continue
            key = str(url.copy_with(fragment=None))
            if key in store.pages or key in picked:
                continue
            if self.unsafe(url):
                if key not in store.skipped:
                    store.skipped.append(key)
                continue
            picked.append(key)
            if len(picked) >= self.settings.max_robots_urls:
                break
        await self.gather([(url, "robots_sitemap") for url in picked])

    def _parse_html_pages(self) -> None:
        store = self.store
        for page in store.pages.values():
            if page.status is not None and page.is_html and page.body:
                info = parse_html(page.text)
                store.html[page.url] = info
                for ref in info.urls:
                    url = self.absolute(ref, page.final_url)
                    if url is not None and url.query:
                        for name, _ in parse_qsl(url.query.decode(), keep_blank_values=True):
                            entry = (page.url, str(url), name)
                            if entry not in store.url_params:
                                store.url_params.append(entry)

    async def _favicon(self) -> None:
        store = self.store
        ref = "/favicon.ico"
        info = store.html.get(store.landing.url) if store.landing else None
        base = store.landing.final_url if store.landing else None
        if info:
            for href in info.icon_hrefs:
                url = self.absolute(href, base)
                if url is not None and self.same_host(url):
                    ref = str(url)
                    break
        url = self.absolute(ref, base)
        if url is None:
            return
        page = await self.get(url, "favicon")
        if page and page.ok and page.body and not page.is_html:
            store.favicon = page

    async def _javascript(self) -> None:
        store = self.store
        wanted: list[str] = []
        for page in list(store.pages.values()):
            info = store.html.get(page.url)
            if info is None or not page.ok:
                continue
            refs = [s.src for s in info.scripts] + info.modulepreloads
            for ref in refs:
                url = self.absolute(ref, page.final_url)
                if url is None:
                    continue
                if not self.same_host(url):
                    if (page.url, str(url)) not in store.third_party_scripts:
                        store.third_party_scripts.append((page.url, str(url)))
                    continue
                key = str(url.copy_with(fragment=None))
                if key not in wanted and key not in store.pages:
                    wanted.append(key)
            for ref in info.source_maps:
                url = self.absolute(ref, page.final_url)
                if url is not None and str(url) not in store.source_maps:
                    store.source_maps.append(str(url))
        wanted = wanted[: self.settings.max_js_files]
        pages = await self.gather(
            [(url, "js") for url in wanted], max_bytes=self.settings.max_js_bytes
        )
        for page in pages:
            if page is None or not page.ok:
                continue
            store.js.append(page)
            for ref in source_maps_in(page.text):
                url = self.absolute(ref, page.final_url)
                if url is not None and str(url) not in store.source_maps:
                    store.source_maps.append(str(url))

    def _finalise(self) -> None:
        store = self.store
        for page in store.pages.values():
            if page.source in ("baseline", "landing"):
                continue
            page.soft_404 = store.is_soft_404(page)
            info = store.html.get(page.url)
            if info is None and page.status is not None and page.is_html and page.body:
                info = parse_html(page.text)
                store.html[page.url] = info
            page.tags |= tag_page(page, info)

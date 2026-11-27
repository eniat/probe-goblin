from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from probegoblin.core.config import Settings
from probegoblin.core.context import TargetContext
from probegoblin.core.discovery import PageStore, tag_page
from probegoblin.core.htmlparse import parse_html
from probegoblin.core.http_client import SafeClient, Scope
from probegoblin.core.models import Hop, Page

FIXTURES = Path(__file__).parent / "fixtures"
TARGET = "https://app.example.com/"


def run(coro):
    return asyncio.run(coro)


def fast_settings(**overrides) -> Settings:
    overrides.setdefault("rate", 1000)
    overrides.setdefault("concurrency", 10)
    return Settings(**overrides)


def make_page(
    url: str,
    status: int = 200,
    headers: list[tuple[str, str]] | None = None,
    body: str | bytes = "",
    source: str = "known_path",
) -> Page:
    headers = list(headers or [])
    if not any(k.lower() == "content-type" for k, _ in headers):
        headers.append(("Content-Type", "text/html"))
    raw = body.encode() if isinstance(body, str) else body
    return Page(
        url=url,
        source=source,
        status=status,
        final_url=url,
        headers=headers,
        body=raw,
        chain=[Hop(url=url, status=status, headers=headers)],
    )


def make_ctx(pages: list[Page], settings: Settings | None = None, target: str = TARGET):
    settings = settings or fast_settings()
    store = PageStore(target=target)
    for page in pages:
        store.pages[page.url] = page
        if page.is_html and page.body:
            store.html[page.url] = parse_html(page.text)
        page.tags |= tag_page(page, store.html.get(page.url))
    store.landing = pages[0]
    store.landing.tags.add("landing")
    scope = Scope.from_url(target)
    client = SafeClient(settings, scope)
    return TargetContext(
        target=target,
        host=scope.host,
        scheme=scope.scheme,
        port=scope.port,
        settings=settings,
        client=client,
        store=store,
    )


@pytest.fixture
def no_sleep(monkeypatch):
    """Make asyncio.sleep instant and record requested delays."""
    delays: list[float] = []
    real_sleep = asyncio.sleep

    async def fake(delay, *args, **kwargs):
        delays.append(delay)
        await real_sleep(0)

    monkeypatch.setattr("probegoblin.core.http_client.asyncio.sleep", fake)
    return delays


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch, tmp_path_factory):
    """No API keys, and cache and data directories that never touch the real home."""
    for key in ("NVD_API_KEY", "SNYK_TOKEN", "SNYK_ORG_ID", "GITHUB_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    # Playwright finds its browsers under $XDG_CACHE_HOME/ms-playwright, so pin the real
    # location before the cache is moved to a temporary folder.
    if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        real_cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
        monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(real_cache / "ms-playwright"))
    base = tmp_path_factory.mktemp("xdg")
    monkeypatch.setenv("XDG_CACHE_HOME", str(base / "cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(base / "data"))

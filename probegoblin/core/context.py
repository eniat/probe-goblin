"""Per-target state shared by every module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from probegoblin.core.config import Settings
from probegoblin.core.discovery import PageStore, tag_page
from probegoblin.core.htmlparse import parse_html
from probegoblin.core.http_client import SafeClient
from probegoblin.core.models import ModuleResult, Page


@dataclass
class Technology:
    name: str
    version: str | None = None
    categories: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    cpe: str | None = None

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}" if self.version else self.name


@dataclass
class TargetContext:
    target: str
    host: str
    scheme: str
    port: int
    settings: Settings
    client: SafeClient
    store: PageStore
    ips: list[str] = field(default_factory=list)
    cdn: str | None = None
    browser: Any = None
    browser_reason: str = "browser stage is not part of this build yet"
    tech: list[Technology] = field(default_factory=list)
    shared: dict[str, Any] = field(default_factory=dict)
    results: dict[str, ModuleResult] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def https(self) -> bool:
        return self.scheme == "https"

    async def fetch(self, url: str, module: str, method: str = "GET", **kwargs) -> Page:
        """Fetch once: plain GETs already in the page store are not requested again."""
        plain = method == "GET" and set(kwargs) <= {"max_bytes"}
        if plain and url in self.store.pages:
            return self.store.pages[url]
        page = await self.client.fetch(url, method, module=module, source=module, **kwargs)
        if page.status is not None:
            page.soft_404 = self.store.is_soft_404(page)
            info = parse_html(page.text) if page.is_html and page.body else None
            page.tags |= tag_page(page, info)
            if plain:
                self.store.pages[url] = page
                if info is not None:
                    self.store.html[url] = info
        return page

    def has_tech(self, name: str) -> bool:
        name = name.lower()
        return any(t.name.lower() == name for t in self.tech)

    def cookie_placeholder(self) -> list[str]:
        """curl arguments for supplied cookies and headers, as placeholders."""
        args = []
        if self.settings.cookie:
            args.append("-H 'Cookie: <cookie>'")
        for name in self.settings.headers:
            args.append(f"-H '{name}: <value>'")
        return args

    def curl(self, url: str, *flags: str) -> str:
        parts = ["curl", *flags, *self.cookie_placeholder()]
        if self.settings.pinned_ip:
            port = self.port
            parts.append(f"--resolve '{self.host}:{port}:{self.settings.pinned_ip}'")
        parts.append(f"'{url}'")
        return " ".join(parts)

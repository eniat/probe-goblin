"""RobotsGoblin: interesting robots.txt and sitemap entries. Recorded, never assumed sensitive."""

from __future__ import annotations

import re

import httpx

from probegoblin.core.context import TargetContext
from probegoblin.core.models import ModuleResult, Status
from probegoblin.core.registry import Goblin

INTERESTING = re.compile(
    r"admin|backup|\.bak|staging|stage|test|dev|internal|api|config|old|private|secret|debug|"
    r"tmp|temp|upload|console|dashboard|manage|\.git|sql|dump|log|phpmyadmin|cgi-bin",
    re.I,
)


class RobotsGoblin(Goblin):
    name = "RobotsGoblin"
    flag = "robots"
    prefix = "ROB"
    order = 110
    description = "Interesting robots.txt and sitemap entries (no extra requests)"

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        store = ctx.store
        robots_url = str(httpx.URL(ctx.target).join("/robots.txt"))
        if not (store.robots and store.robots.ok and not store.robots.is_html):
            result.findings.append(
                self.finding(
                    title="robots.txt not present",
                    status=Status.OK,
                    affected_url=robots_url,
                    observed=f"Status {store.robots.status if store.robots else 'not fetched'}",
                    why_it_matters="Check passed.",
                )
            )
        lines = []
        for entry in store.robots_entries:
            key, _, value = entry.partition(":")
            value = value.strip()
            if key == "Sitemap" or not INTERESTING.search(value):
                continue
            url = httpx.URL(ctx.target).join(value)
            page = store.pages.get(str(url))
            status = (
                f"status {page.status}" + (" (soft 404)" if page.soft_404 else "")
                if page and page.status
                else "not requested"
            )
            lines.append(f"{entry} -> {status}")
        sitemap = [u for u in store.sitemap_entries if INTERESTING.search(httpx.URL(u).path)]
        if lines:
            result.findings.append(
                self.finding(
                    title="Interesting robots.txt entries",
                    status=Status.OBSERVATION,
                    affected_url=robots_url,
                    observed="\n".join(lines[:25]),
                    why_it_matters=(
                        "Paths listed in robots.txt are public. These names suggest areas worth "
                        "reviewing; listing them is not a problem by itself."
                    ),
                    reproduce=[ctx.curl(robots_url, "-s")],
                    manual_steps=["Browse each path through Burp and check access control."],
                )
            )
        if sitemap:
            result.findings.append(
                self.finding(
                    title="Interesting sitemap entries",
                    status=Status.OBSERVATION,
                    affected_url=store.sitemaps[0].url if store.sitemaps else robots_url,
                    observed="\n".join(sitemap[:25]),
                    why_it_matters="Informational. These URLs are published in the sitemap.",
                )
            )
        if store.offhost_urls:
            result.findings.append(
                self.finding(
                    title="Off-host URLs in robots.txt or sitemaps (not requested)",
                    status=Status.OBSERVATION,
                    affected_url=robots_url,
                    observed="\n".join(store.offhost_urls[:25]),
                    why_it_matters="Informational. These hosts were not contacted.",
                )
            )
        return result

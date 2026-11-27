"""HostGoblin: Host and X-Forwarded-Host reflection on the landing page."""

from __future__ import annotations

import re

from probegoblin.core.context import TargetContext
from probegoblin.core.models import Finding, ModuleResult, Page, Status
from probegoblin.core.registry import Goblin

CANARY = "probegoblin.invalid"
PLACES = [
    ("canonical tag", re.compile(r"<link[^>]+rel=[\"']?canonical[^>]+" + re.escape(CANARY), re.I)),
    ("script source", re.compile(r"<script[^>]+src=[\"']?[^\"'>]*" + re.escape(CANARY), re.I)),
    ("absolute link", re.compile(r"(?:href|action|src)=[\"']?https?://" + re.escape(CANARY), re.I)),
    ("meta tag", re.compile(r"<meta[^>]+" + re.escape(CANARY), re.I)),
]


def reflections(page: Page) -> list[str]:
    found = []
    location = page.chain[0].header("location") if page.chain else None
    if location and CANARY in location.lower():
        found.append(f"Location header: {location}")
    for key, value in page.headers:
        if key.lower() != "location" and CANARY in value.lower():
            found.append(f"{key} header: {value[:120]}")
    text = page.text
    for label, pattern in PLACES:
        if pattern.search(text):
            found.append(label)
    if CANARY in text.lower() and not any(p in found for p, _ in PLACES):
        index = text.lower().index(CANARY)
        snippet = " ".join(text[max(0, index - 40) : index + 60].split())
        found.append(f"body: ...{snippet}...")
    return found


class HostGoblin(Goblin):
    name = "HostGoblin"
    flag = "host"
    prefix = "HST"
    order = 90
    description = "Host and X-Forwarded-Host header reflection"

    def estimate_requests(self, settings) -> int:
        return 2

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        url = ctx.store.landing.url
        for header in ("Host", "X-Forwarded-Host"):
            page = await ctx.fetch(url, self.name, headers={header: CANARY}, follow_redirects=False)
            result.findings.append(self._assess(ctx, url, header, page))
        return result

    def _assess(self, ctx: TargetContext, url: str, header: str, page: Page) -> Finding:
        command = ctx.curl(url, "-s", "-D -", f"-H '{header}: {CANARY}'") + f" | grep -i {CANARY}"
        if page.status is None:
            return self.not_assessed(url, f"{header} reflection", page.error or "no response")
        found = reflections(page)
        if found:
            return self.finding(
                title=f"{header} header reflected",
                status=Status.MANUAL_CHECK,
                affected_url=url,
                observed=f"{header}: {CANARY} -> status {page.status}\nReflected in: "
                + "; ".join(found),
                expected="Unknown hosts rejected, or links built from a configured hostname",
                why_it_matters=(
                    "If the reflected value reaches a cache, password reset email or redirect, "
                    "it may allow cache poisoning or reset link poisoning."
                ),
                remediation=(
                    "Build absolute URLs from a configured hostname and reject unknown Host "
                    "values."
                ),
                reproduce=[command],
                manual_steps=[
                    "Check whether the reflection is cached (repeat without the header).",
                    "Trigger a password reset with the header set and inspect the emailed link.",
                ],
                references=[
                    "https://portswigger.net/web-security/host-header",
                ],
            )
        return self.finding(
            title=f"{header} header not reflected",
            status=Status.OK,
            affected_url=url,
            observed=f"{header}: {CANARY} -> status {page.status}, not reflected",
            why_it_matters="Check passed.",
        )

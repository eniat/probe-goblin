"""IPGoblin: does each resolved IP serve the application directly?"""

from __future__ import annotations

import difflib
import ipaddress

from probegoblin.core.context import TargetContext
from probegoblin.core.discovery import COMPARE_BYTES
from probegoblin.core.htmlparse import parse_html
from probegoblin.core.http_client import PURPOSE_DIRECT_IP
from probegoblin.core.models import Finding, ModuleResult, Page, Status, Table
from probegoblin.core.registry import Goblin

MAX_IPS = 4


def ip_url(scheme: str, ip: str) -> str:
    host = f"[{ip}]" if ipaddress.ip_address(ip).version == 6 else ip
    return f"{scheme}://{host}/"


def title(page: Page) -> str:
    return parse_html(page.text).title if page.is_html and page.body else ""


def similarity(a: Page, b: Page) -> float:
    return difflib.SequenceMatcher(
        None, a.body[:COMPARE_BYTES], b.body[:COMPARE_BYTES], autojunk=False
    ).ratio()


def verdict(landing: Page, page: Page) -> str:
    if page.status is None:
        return "not reachable"
    if page.offsite_redirect:
        return f"redirects to {page.offsite_redirect}"
    same_title = title(page) and title(page) == title(landing)
    if page.status == landing.status and (same_title or similarity(page, landing) > 0.9):
        return "serves the same application"
    return f"responds with different content (status {page.status})"


class IPGoblin(Goblin):
    name = "IPGoblin"
    flag = "direct-ip"
    prefix = "DIP"
    order = 170
    description = "Direct HTTP and HTTPS access to each resolved IP"

    def estimate_requests(self, settings) -> int:
        return MAX_IPS * 2

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        landing = ctx.store.landing
        rows = []
        for ip in ctx.ips[:MAX_IPS]:
            for scheme in ("http", "https"):
                url = ip_url(scheme, ip)
                page = await ctx.fetch(url, self.name, purpose=PURPOSE_DIRECT_IP)
                outcome = verdict(landing, page)
                cdn = f" ({ctx.cdn})" if ctx.cdn else ""
                rows.append([url, outcome + cdn])
                result.findings.append(self._finding(ctx, url, outcome, page))
        result.tables.append(Table(title="Direct IP access", columns=["URL", "Result"], rows=rows))
        return result

    def _finding(self, ctx: TargetContext, url: str, outcome: str, page: Page) -> Finding:
        reproduce = [f"curl -sk -o /dev/null -w '%{{http_code}}\\n' '{url}'"]
        if outcome == "serves the same application":
            cdn_note = (
                f" The IP belongs to {ctx.cdn}, so this is the CDN edge, not the origin."
                if ctx.cdn
                else " Controls that rely on the hostname (virtual host rules, a WAF in front "
                "of the hostname) may not apply."
            )
            return self.finding(
                title="Direct IP access possible, serves the same application",
                status=Status.OBSERVATION,
                affected_url=url,
                observed=f"Status {page.status}, same content as {ctx.target}",
                why_it_matters="The application answers without the hostname." + cdn_note,
                reproduce=reproduce,
                manual_steps=[
                    "Check whether security headers and WAF behaviour match the hostname."
                ],
            )
        return self.finding(
            title="Direct IP access",
            status=Status.OK,
            affected_url=url,
            observed=outcome,
            why_it_matters="Check passed.",
        )

"""MethodsGoblin: methods advertised by OPTIONS. Nothing other than OPTIONS is ever sent.

nmap's http-methods script is not used: it sends POST and a random method on every run,
which breaks the GET, HEAD and OPTIONS only rule.
"""

from __future__ import annotations

from probegoblin.core.context import TargetContext
from probegoblin.core.models import Finding, ModuleResult, Status, Table
from probegoblin.core.registry import Goblin

MAX_URLS = 5
RISKY = {"PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "PATCH"}
WEBDAV = {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH"}


def methods_in(value: str | None) -> list[str]:
    return [m.strip().upper() for m in (value or "").split(",") if m.strip()]


class MethodsGoblin(Goblin):
    name = "MethodsGoblin"
    flag = "methods"
    prefix = "MTH"
    order = 150
    description = "Methods advertised by OPTIONS (risky methods listed, never sent)"

    def estimate_requests(self, settings) -> int:
        return MAX_URLS

    def urls(self, ctx: TargetContext) -> list[str]:
        landing = ctx.store.landing
        urls = [landing.final_url or landing.url]
        api_paths = set(ctx.settings.api_paths)
        for page in ctx.store.all_pages():
            path = page.url.removeprefix(ctx.target.rstrip("/"))
            if page.ok and (path in api_paths or "api_docs" in page.tags):
                url = page.final_url or page.url
                if url not in urls:
                    urls.append(url)
        return urls[:MAX_URLS]

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        rows = []
        for url in self.urls(ctx):
            page = await ctx.fetch(url, self.name, "OPTIONS", follow_redirects=False)
            if page.status is None:
                rows.append([url, "-", page.error or "no response", "-"])
                continue
            allow = methods_in(page.header("allow")) + methods_in(page.header("public"))
            cors = methods_in(page.header("access-control-allow-methods"))
            dav = page.header("dav")
            rows.append([url, str(page.status), ", ".join(allow) or "-", ", ".join(cors) or "-"])
            result.findings.append(self._assess(ctx, url, page.status, allow, cors, dav))
        result.tables.append(
            Table(
                title="OPTIONS responses",
                columns=["URL", "Status", "Allow", "Access-Control-Allow-Methods"],
                rows=rows,
            )
        )
        return result

    def _assess(
        self,
        ctx: TargetContext,
        url: str,
        status: int,
        allow: list[str],
        cors: list[str],
        dav: str | None,
    ) -> Finding:
        advertised = sorted(set(allow + cors))
        risky = [m for m in advertised if m in RISKY | WEBDAV]
        reproduce = [
            ctx.curl(url, "-s", "-i", "-X OPTIONS")
            + " | grep -iE '^(allow|public|dav|access-control-allow-methods):'"
        ]
        if risky or dav:
            shown = ", ".join(risky) + (f"; DAV: {dav}" if dav else "")
            return self.finding(
                title="Risky methods advertised, not tested",
                status=Status.MANUAL_CHECK,
                affected_url=url,
                observed=f"OPTIONS {status}: {shown}",
                why_it_matters=(
                    "Advertised only. PUT, DELETE or WebDAV methods may let files be changed; "
                    "TRACE can reflect headers. ProbeGoblin never sends them."
                ),
                remediation="Disable methods the application does not use.",
                reproduce=reproduce,
                manual_steps=[
                    "If the engagement allows it, test each method in Burp against a "
                    "harmless path and confirm whether it is really accepted.",
                    "Many servers list methods in Allow that the application rejects.",
                ],
            )
        return self.finding(
            title="Advertised methods",
            status=Status.OK,
            affected_url=url,
            observed=f"OPTIONS {status}: {', '.join(advertised) or 'no Allow header'}",
            why_it_matters="Check passed.",
        )

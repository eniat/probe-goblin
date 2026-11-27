"""CacheGoblin: caching headers on sensitive pages and API responses."""

from __future__ import annotations

import re

from probegoblin.core.context import TargetContext
from probegoblin.core.cookies import SESSION, parse_set_cookie, purpose
from probegoblin.core.findings import merge_across_pages
from probegoblin.core.models import Finding, ModuleResult, Page, Status
from probegoblin.core.registry import Goblin

TOKEN_FIELD = re.compile(r"csrf|xsrf|_token|authenticity|requestverificationtoken|nonce", re.I)
REF = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
MAX_COMPARE = 4


def parse_cache_control(value: str | None) -> dict[str, str]:
    directives: dict[str, str] = {}
    for part in (value or "").split(","):
        name, _, arg = part.strip().partition("=")
        if name:
            directives.setdefault(name.strip().lower(), arg.strip().strip('"'))
    return directives


def max_age(directives: dict[str, str], name: str = "max-age") -> int | None:
    value = directives.get(name)
    return int(value) if value is not None and value.isdigit() else None


def policy_label(page: Page) -> str:
    parts = []
    for header in ("cache-control", "pragma", "expires", "vary"):
        value = page.header(header)
        if value:
            parts.append(f"{header.title()}: {value}")
    return "; ".join(parts) or "No caching headers"


class CacheGoblin(Goblin):
    name = "CacheGoblin"
    flag = "cache"
    prefix = "CCH"
    order = 50
    description = "Cache-Control, Pragma, Expires and Vary on sensitive pages and API responses"

    def estimate_requests(self, settings) -> int:
        return MAX_COMPARE if settings.cookie else 0

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        sensitive = ctx.store.tagged("login", "account", "password_reset")
        api = [
            p
            for p in ctx.store.all_pages()
            if p.ok and ("api_docs" in p.tags or p.content_type.endswith("json"))
        ]
        targets = list({p.final_url or p.url: p for p in sensitive + api}.values())
        if not targets:
            result.not_assessed_reason = "no login, account, password reset or API responses"
            return result
        findings: list[Finding] = []
        for page in targets:
            findings.extend(self._assess(ctx, page))
        findings.extend(self._consistency(ctx, sensitive))
        findings.extend(self._static_context(ctx))
        if ctx.settings.cookie:
            findings.extend(await self._compare(ctx, sensitive + api))
        result.findings = merge_across_pages(findings)
        return result

    def _contains_sensitive(self, ctx: TargetContext, page: Page) -> tuple[bool, str]:
        reasons = []
        info = ctx.store.info(page)
        if info and any(f.has_password for f in info.forms):
            reasons.append("password form")
        if info and any(TOKEN_FIELD.search(name) for f in info.forms for _, name in f.inputs):
            reasons.append("anti-CSRF token")
        for raw in page.header_all("set-cookie"):
            cookie = parse_set_cookie(raw)
            if cookie and purpose(cookie.name) == SESSION:
                reasons.append(f"sets session cookie {cookie.name}")
        if ctx.settings.cookie and page.tags & {"account", "api_docs"}:
            reasons.append("authenticated response")
        if page.content_type.endswith("json") and ctx.settings.cookie:
            reasons.append("authenticated API response")
        return bool(reasons), ", ".join(dict.fromkeys(reasons))

    def _assess(self, ctx: TargetContext, page: Page) -> list[Finding]:
        url = page.final_url or page.url
        cc = parse_cache_control(page.header("cache-control"))
        observed = policy_label(page)
        sensitive, why_sensitive = self._contains_sensitive(ctx, page)
        context = f" The response contains: {why_sensitive}." if sensitive else ""
        reproduce = [ctx.curl(url, "-sI") + " | grep -iE '^(cache-control|pragma|expires|vary):'"]
        out: list[Finding] = []

        def add(status: Status, title: str, why: str, fix: str | None = None) -> None:
            out.append(
                self.finding(
                    title=title,
                    status=status,
                    affected_url=url,
                    observed=observed,
                    expected="Cache-Control: no-store" if sensitive else None,
                    why_it_matters=why + context,
                    remediation=fix,
                    reproduce=reproduce,
                    references=[REF],
                )
            )

        shared = "public" in cc or (max_age(cc, "s-maxage") or 0) > 0
        stores = "no-store" not in cc
        if "public" in cc and "private" in cc:
            add(Status.OBSERVATION, "Conflicting Cache-Control directives", "public and private.")
        if "no-store" in cc and ((max_age(cc) or 0) > 0 or "public" in cc):
            add(
                Status.OBSERVATION,
                "Conflicting Cache-Control directives",
                "no-store is combined with directives that allow caching. Browsers honour "
                "no-store, but intermediary caches may not agree.",
                "Use Cache-Control: no-store on its own.",
            )
        if shared and stores:
            add(
                Status.ISSUE,
                "Sensitive page cacheable by shared caches",
                "public or s-maxage lets proxies and CDNs store the response and serve it to "
                "other users.",
                "Send Cache-Control: no-store (or private, no-cache at minimum).",
            )
        elif stores and (max_age(cc) or 0) > 0 and "private" not in cc:
            add(
                Status.ISSUE if sensitive else Status.OBSERVATION,
                "Sensitive page cacheable for a long time",
                f"max-age={cc['max-age']} lets caches keep the response.",
                "Send Cache-Control: no-store.",
            )
        elif stores and "no-cache" in cc:
            add(
                Status.ISSUE if sensitive else Status.OBSERVATION,
                "no-cache used without no-store",
                "no-cache still lets the browser and caches store the response; it only forces "
                "revalidation before reuse.",
                "Use no-store to stop the response being written to disk.",
            )
        elif not cc:
            heuristic = page.header("last-modified") or page.header("expires")
            if page.header("pragma") and "no-cache" in page.header("pragma").lower():
                add(
                    Status.OBSERVATION,
                    "Only Pragma: no-cache set",
                    "Pragma is an HTTP/1.0 request header; modern caches ignore it on responses.",
                    "Send Cache-Control: no-store.",
                )
            elif sensitive:
                add(
                    Status.ISSUE if heuristic else Status.OBSERVATION,
                    "No Cache-Control on sensitive page",
                    "Without Cache-Control, browsers and proxies decide for themselves"
                    + (
                        " and may cache heuristically because Last-Modified or Expires is set."
                        if heuristic
                        else "."
                    ),
                    "Send Cache-Control: no-store.",
                )
        elif stores and sensitive:
            add(
                Status.OBSERVATION,
                "Sensitive page without no-store",
                "The response may be written to the browser cache.",
                "Send Cache-Control: no-store.",
            )
        if not out:
            out.append(
                self.finding(
                    title="Caching of sensitive page",
                    status=Status.OK,
                    affected_url=url,
                    observed=observed,
                    why_it_matters="Check passed.",
                )
            )
        return out

    def _consistency(self, ctx: TargetContext, pages: list[Page]) -> list[Finding]:
        policies = {(p.final_url or p.url): policy_label(p) for p in pages}
        if len(set(policies.values())) <= 1:
            return []
        lines = "\n".join(f"{url}: {label}" for url, label in policies.items())
        first = next(iter(policies))
        return [
            self.finding(
                title="Inconsistent caching policy across sensitive pages",
                status=Status.OBSERVATION,
                affected_url=first,
                observed=lines,
                why_it_matters="Some sensitive pages are protected and others are not.",
                remediation="Apply one Cache-Control policy to every sensitive page.",
            )
        ]

    def _static_context(self, ctx: TargetContext) -> list[Finding]:
        static = [p for p in ctx.store.all_pages() if p.ok and "static" in p.tags][:3]
        if not static:
            return []
        lines = "\n".join(f"{p.final_url or p.url}: {policy_label(p)}" for p in static)
        return [
            self.finding(
                title="Caching on static resources (for comparison)",
                status=Status.OBSERVATION,
                affected_url=static[0].final_url or static[0].url,
                observed=lines,
                why_it_matters="Informational. Static files are expected to be cacheable.",
            )
        ]

    async def _compare(self, ctx: TargetContext, pages: list[Page]) -> list[Finding]:
        out: list[Finding] = []
        for page in pages[:MAX_COMPARE]:
            url = page.final_url or page.url
            anon = await ctx.fetch(url, self.name, omit_auth=True, follow_redirects=False)
            if anon.status is None:
                continue
            auth_cc = page.header("cache-control") or "none"
            anon_cc = anon.header("cache-control") or "none"
            if anon.status == page.status and anon.body_hash == page.body_hash:
                out.append(
                    self.finding(
                        title="Same response with and without the supplied session",
                        status=Status.OBSERVATION,
                        affected_url=url,
                        observed=f"Status {page.status} both ways, identical body",
                        why_it_matters=(
                            "The page does not depend on the session, or the supplied cookie "
                            "is not valid. Authenticated caching could not be compared."
                        ),
                        manual_steps=["Check the supplied cookie still logs you in."],
                    )
                )
            elif auth_cc != anon_cc:
                out.append(
                    self.finding(
                        title="Caching differs between authenticated and anonymous responses",
                        status=Status.OBSERVATION,
                        affected_url=url,
                        observed=f"With session: {auth_cc}\nWithout session: {anon_cc}",
                        why_it_matters="Informational. Check the authenticated policy is the "
                        "stricter one.",
                        reproduce=[ctx.curl(url, "-sI") + " | grep -i '^cache-control:'"],
                    )
                )
        return out

"""RedirectGoblin: HTTPS enforcement, redirect behaviour, mixed content, redirect parameters."""

from __future__ import annotations

import re

import httpx

from probegoblin.core.context import TargetContext
from probegoblin.core.findings import merge_across_pages
from probegoblin.core.htmlparse import ACTIVE
from probegoblin.core.http_client import PURPOSE_HTTP_CHECK
from probegoblin.core.models import Finding, ModuleResult, Status
from probegoblin.core.registry import Goblin

REDIRECT_PARAMS = {
    "next",
    "url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "returnurl",
    "return_url",
    "return_to",
    "returnto",
    "continue",
    "dest",
    "destination",
    "goto",
    "target",
    "callback",
}
PERMANENT = {301, 308}


class RedirectGoblin(Goblin):
    name = "RedirectGoblin"
    flag = "redirects"
    prefix = "RED"
    order = 80
    uses_browser = True
    description = "HTTP to HTTPS redirect, downgrades, chains, mixed content, redirect parameters"

    def estimate_requests(self, settings) -> int:
        return 1 + settings.max_redirects

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        result.findings.extend(await self._https_enforcement(ctx))
        result.findings.extend(self._downgrades(ctx))
        result.findings.extend(self._chains(ctx))
        result.findings.extend(merge_across_pages(self._mixed_content(ctx)))
        result.findings.extend(self._redirect_params(ctx))
        if ctx.browser is None:
            result.findings.append(
                self.not_assessed(
                    ctx.target,
                    "Mixed content seen by the browser",
                    f"{ctx.browser_reason}; mixed content was checked from HTML only",
                )
            )
        else:
            result.findings.extend(self._browser_mixed(ctx))
        return result

    def _browser_mixed(self, ctx: TargetContext) -> list[Finding]:
        active: dict[str, list[str]] = {}
        passive: dict[str, list[str]] = {}
        for message in ctx.browser.console:
            if "Mixed Content" not in message.text:
                continue
            match = re.search(r"requested an insecure (\w[\w ]*?) '([^']+)'", message.text)
            if not match:
                continue
            kind, url = match.groups()
            bucket = passive if kind.split()[0] in ("image", "video", "audio") else active
            entries = bucket.setdefault(message.page_url, [])
            if f"{kind}: {url}" not in entries:
                entries.append(f"{kind}: {url}")
        for response in ctx.browser.responses:
            if response.page_url.startswith("https://") and response.url.startswith("http://"):
                bucket = passive if response.resource_type in ("image", "media") else active
                entries = bucket.setdefault(response.page_url, [])
                label = f"{response.resource_type}: {response.url}"
                if label not in entries:
                    entries.append(label)
        out: list[Finding] = []
        for page_url, items in active.items():
            out.append(
                self.finding(
                    title="Active mixed content seen by the browser",
                    status=Status.ISSUE,
                    affected_url=page_url,
                    observed="\n".join(items[:10]),
                    why_it_matters="The browser requested scripts, styles or frames over HTTP; "
                    "Chromium blocks most, which can also break the page.",
                    remediation="Load every subresource over HTTPS.",
                    reproduce=[ctx.curl(page_url, "-s") + " | grep -c 'http://'"],
                    manual_steps=[
                        "Open the page with DevTools, Console tab, and check for "
                        "Mixed Content messages."
                    ],
                )
            )
        for page_url, items in passive.items():
            out.append(
                self.finding(
                    title="Passive mixed content seen by the browser",
                    status=Status.OBSERVATION,
                    affected_url=page_url,
                    observed="\n".join(items[:10]),
                    why_it_matters="Images or media requested over HTTP; Chromium upgrades or "
                    "blocks many of them.",
                    remediation="Load every subresource over HTTPS.",
                )
            )
        if not out:
            out.append(
                self.finding(
                    title="No mixed content seen by the browser",
                    status=Status.OK,
                    affected_url=ctx.target,
                    why_it_matters="Check passed.",
                )
            )
        return out

    async def _https_enforcement(self, ctx: TargetContext) -> list[Finding]:
        if not ctx.https:
            return [
                self.finding(
                    title="Target scanned over plain HTTP",
                    status=Status.OBSERVATION,
                    affected_url=ctx.target,
                    observed=f"Target URL uses http:// ({ctx.target})",
                    why_it_matters=(
                        "HTTPS was not checked because it is outside the target given. Traffic to "
                        "this URL is unencrypted."
                    ),
                    manual_steps=["Check whether the same site is served over HTTPS."],
                )
            ]
        url = f"http://{ctx.host}/"
        page = await ctx.fetch(url, self.name, purpose=PURPOSE_HTTP_CHECK)
        reproduce = [ctx.curl(url, "-sI")]
        if page.status is None:
            return [
                self.finding(
                    title="Plain HTTP not served",
                    status=Status.OK,
                    affected_url=url,
                    observed=f"No response on port 80 ({page.error})",
                    why_it_matters="Check passed.",
                )
            ]
        first = page.chain[0]
        location = first.header("location")
        if first.status in (301, 302, 303, 307, 308) and location:
            target = httpx.URL(url).join(location)
            hops = " -> ".join(f"{h.status} {h.url}" for h in page.chain)
            if target.scheme != "https":
                ends_https = (page.final_url or "").startswith("https://")
                return [
                    self.finding(
                        title=(
                            "HTTP redirects elsewhere before HTTPS"
                            if ends_https
                            else "HTTP does not redirect to HTTPS"
                        ),
                        status=Status.OBSERVATION if ends_https else Status.ISSUE,
                        affected_url=url,
                        observed=hops
                        + (f" -> {page.offsite_redirect}" if page.offsite_redirect else ""),
                        expected=f"301 to https://{ctx.host}/",
                        why_it_matters="The first hop stays on plain HTTP, open to interception.",
                        remediation="Redirect plain HTTP straight to HTTPS with a 301.",
                        reproduce=reproduce,
                    )
                ]
            out = []
            if target.host != ctx.host:
                out.append(
                    self.finding(
                        title="HTTP redirects to HTTPS on another host",
                        status=Status.OBSERVATION,
                        affected_url=url,
                        observed=f"{first.status} Location: {location}",
                        why_it_matters=(
                            "The redirect also changes the hostname, so HSTS for this host is "
                            "only learnt after a further redirect."
                        ),
                        remediation=f"Redirect to https://{ctx.host}/ first, then canonicalise.",
                        reproduce=reproduce,
                    )
                )
            if first.status not in PERMANENT:
                out.append(
                    self.finding(
                        title="HTTP to HTTPS redirect is not permanent",
                        status=Status.OBSERVATION,
                        affected_url=url,
                        observed=f"{first.status} Location: {location}",
                        expected="301 or 308",
                        why_it_matters="Temporary redirects are not cached by browsers.",
                        remediation="Use 301 or 308.",
                        reproduce=reproduce,
                    )
                )
            if not out:
                out.append(
                    self.finding(
                        title="HTTP redirects to HTTPS",
                        status=Status.OK,
                        affected_url=url,
                        observed=f"{first.status} Location: {location}",
                        why_it_matters="Check passed.",
                    )
                )
            return out
        return [
            self.finding(
                title="Site served over plain HTTP without redirect",
                status=Status.ISSUE,
                affected_url=url,
                observed=f"{first.status} with content, no redirect to HTTPS",
                expected=f"301 to https://{ctx.host}/",
                why_it_matters=(
                    "Visitors who type the hostname or follow an http:// link use the site "
                    "unencrypted."
                ),
                remediation="Redirect every plain HTTP request to HTTPS with a 301.",
                reproduce=reproduce,
            )
        ]

    def _downgrades(self, ctx: TargetContext) -> list[Finding]:
        out: list[Finding] = []
        seen = set()
        for page in ctx.store.all_pages():
            for hop in page.chain:
                location = hop.header("location")
                if not location or not hop.url.startswith("https://"):
                    continue
                target = str(httpx.URL(hop.url).join(location))
                if target.startswith("http://") and (hop.url, target) not in seen:
                    seen.add((hop.url, target))
                    out.append(
                        self.finding(
                            title="HTTPS redirects to plain HTTP",
                            status=Status.ISSUE,
                            affected_url=hop.url,
                            observed=f"{hop.status} Location: {location}",
                            why_it_matters="The user is moved off HTTPS onto an unencrypted URL.",
                            remediation="Keep every redirect on https://.",
                            reproduce=[ctx.curl(hop.url, "-sI") + " | grep -i '^location:'"],
                        )
                    )
        return out

    def _chains(self, ctx: TargetContext) -> list[Finding]:
        out: list[Finding] = []
        hosts = set()
        for page in ctx.store.all_pages():
            if page.error and "redirect loop" in page.error:
                out.append(
                    self.finding(
                        title="Redirect loop",
                        status=Status.OBSERVATION,
                        affected_url=page.url,
                        observed=" -> ".join(f"{h.status} {h.url}" for h in page.chain),
                        why_it_matters="The page never resolves; browsers show an error.",
                        reproduce=[ctx.curl(page.url, "-sIL", "--max-redirs 10")],
                    )
                )
            elif len(page.chain) > 3:
                out.append(
                    self.finding(
                        title="Long redirect chain",
                        status=Status.OBSERVATION,
                        affected_url=page.url,
                        observed=" -> ".join(f"{h.status} {h.url}" for h in page.chain),
                        why_it_matters="Each extra hop is one more request to act on.",
                    )
                )
            if page.offsite_redirect:
                host = httpx.URL(page.offsite_redirect).host
                if host and host != ctx.host:
                    hosts.add((page.url, page.offsite_redirect))
        canonical = [(src, dst) for src, dst in hosts if _same_site(ctx.host, dst)]
        external = [(src, dst) for src, dst in hosts if not _same_site(ctx.host, dst)]
        if canonical:
            src, dst = sorted(canonical)[0]
            out.append(
                self.finding(
                    title="Redirects to another hostname of the same site",
                    status=Status.OBSERVATION,
                    affected_url=src,
                    observed="\n".join(f"{s} -> {d}" for s, d in sorted(canonical)[:5]),
                    why_it_matters=(
                        "Hostname canonicalisation (for example www). The other hostname was "
                        "not requested; scan it as its own target if it is in scope."
                    ),
                )
            )
        if external:
            out.append(
                self.finding(
                    title="Redirects to other hosts (recorded, not followed)",
                    status=Status.OBSERVATION,
                    affected_url=sorted(external)[0][0],
                    observed="\n".join(f"{s} -> {d}" for s, d in sorted(external)[:10]),
                    why_it_matters="Informational. These hosts were not contacted.",
                )
            )
        return out

    def _mixed_content(self, ctx: TargetContext) -> list[Finding]:
        out: list[Finding] = []
        for page in ctx.store.html_pages():
            final = page.final_url or page.url
            if not final.startswith("https://"):
                continue
            info = ctx.store.info(page)
            if info is None:
                continue
            active, passive, forms = [], [], []
            for kind, ref in info.resources:
                if not ref.strip().lower().startswith("http://"):
                    continue
                if kind == "form":
                    forms.append(ref)
                elif kind in ACTIVE:
                    active.append(f"{kind}: {ref}")
                else:
                    passive.append(f"{kind}: {ref}")
            reproduce = [
                ctx.curl(final, "-s") + " | grep -oiE '(src|href|action)=.http://[^\"'\\'' >]+'"
            ]
            if active:
                out.append(
                    self.finding(
                        title="Active mixed content",
                        status=Status.ISSUE,
                        affected_url=final,
                        observed="\n".join(active[:10]),
                        why_it_matters=(
                            "Scripts, styles or frames over HTTP can be altered in transit. "
                            "Browsers block most of them, which also breaks the page."
                        ),
                        remediation="Load every subresource over HTTPS.",
                        reproduce=reproduce,
                    )
                )
            if forms:
                out.append(
                    self.finding(
                        title="Form submits over plain HTTP",
                        status=Status.ISSUE,
                        affected_url=final,
                        observed="\n".join(forms[:5]),
                        why_it_matters="Data entered on an HTTPS page is sent unencrypted.",
                        remediation="Use an https:// form action.",
                        reproduce=reproduce,
                    )
                )
            if passive:
                out.append(
                    self.finding(
                        title="Passive mixed content",
                        status=Status.OBSERVATION,
                        affected_url=final,
                        observed="\n".join(passive[:10]),
                        why_it_matters=(
                            "Images or media over HTTP can be swapped or observed in transit; "
                            "modern browsers upgrade or block many of them."
                        ),
                        remediation="Load every subresource over HTTPS.",
                        reproduce=reproduce,
                    )
                )
        return out

    def _redirect_params(self, ctx: TargetContext) -> list[Finding]:
        hits: dict[str, list[str]] = {}
        sources: dict[str, str] = {}
        for page_url, url, name in ctx.store.url_params:
            if name.lower() in REDIRECT_PARAMS:
                hits.setdefault(name, [])
                if url not in hits[name]:
                    hits[name].append(url)
                    sources.setdefault(url, page_url)
        out = []
        for name, urls in hits.items():
            page = sources[urls[0]]
            out.append(
                self.finding(
                    title=f"Redirect-style parameter '{name}'",
                    status=Status.MANUAL_CHECK,
                    affected_url=urls[0],
                    observed="\n".join(urls[:5]) + f"\nFound on {page}",
                    why_it_matters=(
                        "Parameters like this often control a redirect. Not tested; if the value "
                        "is not validated it may allow an open redirect."
                    ),
                    reproduce=[ctx.curl(page, "-s") + f" | grep -oE '[?&]{name}=[^\"&]*'"],
                    manual_steps=[
                        f"In Burp, set {name} to an external URL and check where the response "
                        "redirects.",
                        "Try scheme-relative (//host), backslash and encoded variants.",
                    ],
                )
            )
        return out


def _same_site(host: str, url: str) -> bool:
    other = httpx.URL(url).host or ""
    return other.removeprefix("www.") == host.removeprefix("www.")

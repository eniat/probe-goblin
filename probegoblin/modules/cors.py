"""CORSGoblin: origin validation on the landing page and API paths."""

from __future__ import annotations

from dataclasses import dataclass

from probegoblin.core.context import TargetContext
from probegoblin.core.models import Finding, ModuleResult, Page, Status
from probegoblin.core.registry import Goblin

MAX_URLS = 5
REF = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
MANUAL = (
    "Repeat the reflected request with a valid session cookie against an authenticated API "
    "endpoint and confirm whether sensitive data is returned with the reflected origin."
)


@dataclass
class Probe:
    label: str
    origin: str


def probes(host: str) -> list[Probe]:
    return [
        Probe("any origin", "https://probegoblin.invalid"),
        Probe("null origin", "null"),
        Probe("prefix match", f"https://{host}.probegoblin.invalid"),
        Probe("suffix match", f"https://probegoblin{host}"),
    ]


@dataclass
class Outcome:
    probe: Probe
    status: int | None
    acao: str | None
    credentials: bool
    vary_origin: bool

    @property
    def reflected(self) -> bool:
        return self.acao is not None and self.acao == self.probe.origin

    @property
    def wildcard(self) -> bool:
        return self.acao == "*"


def outcome(probe: Probe, page: Page) -> Outcome:
    vary = ",".join(page.header_all("vary")).lower()
    return Outcome(
        probe=probe,
        status=page.status,
        acao=(page.header("access-control-allow-origin") or "").strip() or None,
        credentials=(page.header("access-control-allow-credentials") or "").strip().lower()
        == "true",
        vary_origin="origin" in [v.strip() for v in vary.split(",")] or vary.strip() == "*",
    )


class CORSGoblin(Goblin):
    name = "CORSGoblin"
    flag = "cors"
    prefix = "COR"
    order = 70
    description = "Origin reflection, null origin, wildcard and credentials on landing and API"

    def estimate_requests(self, settings) -> int:
        return MAX_URLS * 4

    def urls(self, ctx: TargetContext) -> list[str]:
        urls = [ctx.store.landing.final_url or ctx.store.landing.url]
        api_paths = set(ctx.settings.api_paths)
        for page in ctx.store.all_pages():
            path = page.url.removeprefix(ctx.target.rstrip("/"))
            api = "api_docs" in page.tags or path in api_paths or page.content_type.endswith("json")
            if api and page.ok:
                url = page.final_url or page.url
                if url not in urls:
                    urls.append(url)
        return urls[:MAX_URLS]

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        for url in self.urls(ctx):
            outcomes = []
            default = 443 if ctx.https else 80
            netloc = ctx.host if ctx.port == default else f"{ctx.host}:{ctx.port}"
            for probe in probes(netloc):
                page = await ctx.fetch(
                    url, self.name, headers={"Origin": probe.origin}, follow_redirects=False
                )
                if page.status is not None:
                    outcomes.append(outcome(probe, page))
            api = url != (ctx.store.landing.final_url or ctx.store.landing.url)
            result.findings.extend(self._assess(ctx, url, outcomes, api))
        return result

    def _reproduce(self, ctx: TargetContext, url: str, origin: str) -> list[str]:
        return [
            ctx.curl(url, "-s", "-o /dev/null", "-D -", f"-H 'Origin: {origin}'")
            + " | grep -i '^access-control-'"
        ]

    def _assess(
        self, ctx: TargetContext, url: str, outcomes: list[Outcome], api: bool
    ) -> list[Finding]:
        out: list[Finding] = []
        if not outcomes:
            return [self.not_assessed(url, "CORS probes", "no response to the probes")]
        by_label = {o.probe.label: o for o in outcomes}
        reflected = [o for o in outcomes if o.reflected]

        def observed_for(items: list[Outcome]) -> str:
            lines = []
            for o in items:
                creds = (
                    "Access-Control-Allow-Credentials: true" if o.credentials else "no credentials"
                )
                lines.append(f"Origin: {o.probe.origin} -> ACAO: {o.acao} ({creds})")
            return "\n".join(lines)

        any_origin = by_label.get("any origin")
        null = by_label.get("null origin")
        partial = [
            o
            for o in reflected
            if o.probe.label in ("prefix match", "suffix match")
            and not (any_origin and any_origin.reflected)
        ]
        for item, title in (
            (any_origin, "CORS reflects any origin"),
            (null, "CORS accepts the null origin"),
        ):
            if item is None or not item.reflected:
                continue
            if item.credentials:
                status = Status.ISSUE
                why = (
                    "Any site can make credentialed requests and read the response, so data "
                    "available to a logged-in user can be read cross-origin."
                )
            else:
                status = Status.MANUAL_CHECK if api else Status.OBSERVATION
                why = (
                    "Any site can read responses, but without credentials only data available "
                    "anonymously is exposed."
                )
            if item.probe.label == "null origin":
                why += " Sandboxed iframes and some redirects send Origin: null."
            out.append(
                self.finding(
                    title=title + (" with credentials" if item.credentials else ""),
                    status=status,
                    affected_url=url,
                    observed=observed_for([item]),
                    expected="Only trusted origins in Access-Control-Allow-Origin",
                    why_it_matters=why,
                    remediation="Validate Origin against an exact allowlist of trusted origins.",
                    reproduce=self._reproduce(ctx, url, item.probe.origin),
                    manual_steps=[MANUAL],
                    references=[REF],
                )
            )
        if partial:
            creds = any(o.credentials for o in partial)
            out.append(
                self.finding(
                    title="CORS origin check can be bypassed with a crafted domain",
                    status=(
                        Status.ISSUE
                        if creds
                        else (Status.MANUAL_CHECK if api else Status.OBSERVATION)
                    ),
                    affected_url=url,
                    observed=observed_for(partial),
                    expected="Exact origin comparison",
                    why_it_matters=(
                        "The origin is matched with a starts-with, ends-with or contains check, "
                        "so an attacker-registered domain passes."
                        + (" Credentials are allowed." if creds else "")
                    ),
                    remediation="Compare the full origin against an exact allowlist.",
                    reproduce=self._reproduce(ctx, url, partial[0].probe.origin),
                    manual_steps=[MANUAL],
                    references=[REF],
                )
            )
        wildcard = [o for o in outcomes if o.wildcard]
        if wildcard:
            creds = any(o.credentials for o in wildcard)
            out.append(
                self.finding(
                    title="CORS allows any origin (wildcard)",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed="Access-Control-Allow-Origin: *"
                    + (" with Access-Control-Allow-Credentials: true" if creds else ""),
                    why_it_matters=(
                        "Any site can read anonymous responses."
                        + (
                            " Browsers refuse credentials with a wildcard, so cookies are not "
                            "sent."
                            if creds
                            else ""
                        )
                    ),
                    remediation="Use an allowlist if the responses are not meant to be public.",
                    reproduce=self._reproduce(ctx, url, wildcard[0].probe.origin),
                    references=[REF],
                )
            )
        no_vary = [o for o in reflected if not o.vary_origin]
        if no_vary:
            out.append(
                self.finding(
                    title="Reflected CORS response without Vary: Origin",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=observed_for(no_vary[:1]) + "\nNo Vary: Origin",
                    why_it_matters=(
                        "A shared cache may serve a response with one origin's CORS headers to "
                        "another origin."
                    ),
                    remediation="Add Vary: Origin to responses that set ACAO dynamically.",
                    reproduce=self._reproduce(ctx, url, no_vary[0].probe.origin),
                    references=[REF],
                )
            )
        statuses = {o.status for o in outcomes}
        if len(statuses) > 1:
            out.append(
                self.finding(
                    title="Response status changes with the Origin header",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=", ".join(f"{o.probe.label}: {o.status}" for o in outcomes),
                    why_it_matters="The server treats origins differently; worth a closer look.",
                    reproduce=self._reproduce(ctx, url, outcomes[0].probe.origin),
                )
            )
        if not out:
            out.append(
                self.finding(
                    title="CORS origin validation",
                    status=Status.OK,
                    affected_url=url,
                    observed="No probe origin was accepted",
                    why_it_matters="Check passed.",
                )
            )
        return out

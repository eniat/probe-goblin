"""HeaderGoblin: CSP, HSTS, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy."""

from __future__ import annotations

from collections.abc import Callable

from probegoblin.core import csp
from probegoblin.core.context import TargetContext
from probegoblin.core.findings import merge_across_pages
from probegoblin.core.models import Finding, ModuleResult, Page, Status
from probegoblin.core.registry import Goblin

ONE_YEAR = 31536000
REFERRER_VALUES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}
INFO_HEADERS = (
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
)
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"


def parse_hsts(value: str) -> tuple[dict[str, str], list[str]]:
    directives: dict[str, str] = {}
    problems: list[str] = []
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, val = part.partition("=")
        name = name.strip().lower()
        if name in directives:
            problems.append(f"duplicate {name} directive")
            continue
        directives[name] = val.strip().strip('"')
    if "max-age" not in directives:
        problems.append("no max-age directive")
    elif not directives["max-age"].isdigit():
        problems.append(f"max-age is not a number ({directives['max-age']!r})")
    return directives, problems


class HeaderGoblin(Goblin):
    name = "HeaderGoblin"
    flag = "headers"
    prefix = "HDR"
    order = 20
    description = "CSP, HSTS, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy"

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        findings: list[Finding] = []
        for page in ctx.store.sensitive_pages():
            for check in (self._csp, self._hsts, self._nosniff, self._xss, self._referrer):
                findings.extend(check(ctx, page))
            findings.append(self._informational(ctx, page))
        result.findings = merge_across_pages(findings)
        return result

    def _reproduce(self, ctx: TargetContext, page: Page, header: str) -> list[str]:
        url = page.url
        return [ctx.curl(url, "-sI", "-L") + f" | grep -i '^{header}'"]

    # Content-Security-Policy

    def _csp(self, ctx: TargetContext, page: Page) -> list[Finding]:
        url = page.url
        policies = csp.page_policies(page, ctx.store.info(page))
        enforced = [p for p in policies if p.enforced]
        report_only = [p for p in policies if p.report_only]
        rep = self._reproduce(ctx, page, "content-security-policy")
        if not enforced:
            observed = "Header absent, no meta policy"
            if report_only:
                observed = f"Report-Only only: {report_only[0].raw}"
            return [
                self.finding(
                    title="Content-Security-Policy not enforced",
                    status=Status.ISSUE,
                    affected_url=url,
                    observed=observed,
                    expected=(
                        "Enforced policy with default-src, script-src, object-src 'none' "
                        "and base-uri"
                    ),
                    why_it_matters=(
                        "No browser-enforced restriction on script sources if an injection "
                        "point exists."
                    ),
                    remediation="Define and enforce a CSP, starting in Report-Only to tune it.",
                    reproduce=rep,
                    references=[MDN + "Content-Security-Policy"],
                )
            ]
        findings: list[Finding] = []
        shown = " | ".join(f"[{p.source}] {p.raw}" for p in enforced)

        def every(problem: Callable[[csp.Policy], str | None]) -> str | None:
            """A weakness counts only if every enforced policy has it."""
            details = [problem(p) for p in enforced]
            return details[0] if all(details) else None

        def add(status: Status, title: str, detail: str, why: str, fix: str | None) -> None:
            findings.append(
                self.finding(
                    title=title,
                    status=status,
                    affected_url=url,
                    observed=f"{detail}\nPolicy: {shown}",
                    why_it_matters=why,
                    remediation=fix,
                    reproduce=rep,
                    references=[MDN + "Content-Security-Policy"],
                )
            )

        def ok(title: str, detail: str) -> None:
            findings.append(
                self.finding(
                    title=title,
                    status=Status.OK,
                    affected_url=url,
                    observed=detail,
                    why_it_matters="Check passed.",
                )
            )

        def script_sources(p: csp.Policy) -> list[str]:
            return p.effective("script-src")[1] or []

        def strict_dynamic(p: csp.Policy) -> bool:
            return "'strict-dynamic'" in script_sources(p)

        no_scripts = every(
            lambda p: None if p.effective("script-src")[0] else "No script-src or default-src"
        )
        if no_scripts:
            add(
                Status.ISSUE,
                "CSP does not restrict scripts",
                no_scripts,
                "Without script-src or default-src the policy places no limit on scripts.",
                "Add script-src (or default-src) with nonces or hashes.",
            )
        else:
            inline = every(
                lambda p: (
                    "script-src allows 'unsafe-inline' with no nonce, hash or 'strict-dynamic'"
                    if "'unsafe-inline'" in script_sources(p)
                    and not csp.has_nonce_or_hash(script_sources(p))
                    and not strict_dynamic(p)
                    else None
                )
            )
            if inline:
                add(
                    Status.ISSUE,
                    "CSP allows inline scripts",
                    inline,
                    "Injected inline script would run, so the policy does not stop most XSS.",
                    "Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
                )
            elif any("'unsafe-inline'" in script_sources(p) for p in enforced):
                ok("CSP 'unsafe-inline' neutralised", "Nonce, hash or 'strict-dynamic' present")
            else:
                ok("CSP blocks inline scripts", "No 'unsafe-inline' in script sources")

            wild = every(
                lambda p: (
                    None
                    if strict_dynamic(p)
                    else (
                        (
                            "Script sources include "
                            + ", ".join(
                                s for s in script_sources(p) if s == "*" or s in csp.SCHEME_SOURCES
                            )
                        )
                        if any(s == "*" or s in csp.SCHEME_SOURCES for s in script_sources(p))
                        else None
                    )
                )
            )
            if wild:
                add(
                    Status.ISSUE,
                    "CSP allows scripts from any host or scheme",
                    wild,
                    "Any site, or data: and blob: URLs, can supply script, so the allowlist "
                    "does not limit an attacker.",
                    "Remove *, http:, https:, data: and blob: from script sources.",
                )
            bypass = every(
                lambda p: (
                    None
                    if strict_dynamic(p)
                    else ", ".join(
                        f"{source} ({kind})"
                        for source, kind in csp.bypass_hosts(
                            script_sources(p), "'unsafe-eval'" in script_sources(p)
                        )
                    )
                    or None
                )
            )
            if bypass:
                add(
                    Status.ISSUE,
                    "CSP allowlists hosts with known bypasses",
                    f"Allowlisted: {bypass}",
                    "These hosts serve JSONP endpoints or script libraries that let an "
                    "attacker run script within the allowlist.",
                    "Replace host allowlists with nonces or hashes plus 'strict-dynamic'.",
                )
            broad = every(
                lambda p: (
                    None
                    if strict_dynamic(p)
                    else ", ".join(csp.broad_wildcards(script_sources(p))) or None
                )
            )
            if broad:
                add(
                    Status.OBSERVATION,
                    "CSP allows wildcard subdomains for scripts",
                    f"Wildcard sources: {broad}",
                    "Any subdomain of these hosts can supply script, including ones the "
                    "site does not control.",
                    "List exact hosts, or move to nonces or hashes.",
                )
            evals = every(
                lambda p: (
                    "script-src allows 'unsafe-eval'"
                    if "'unsafe-eval'" in script_sources(p)
                    else None
                )
            )
            if evals:
                add(
                    Status.OBSERVATION,
                    "CSP allows eval",
                    evals,
                    "eval() and similar calls are allowed, which some injection techniques use.",
                    "Remove 'unsafe-eval' if the application does not need it.",
                )

        objects = every(
            lambda p: (
                None
                if (p.effective("object-src")[1] or []) == ["'none'"]
                else (
                    "No object-src or default-src"
                    if p.effective("object-src")[0] is None
                    else f"{p.effective('object-src')[0]} {' '.join(p.effective('object-src')[1])}"
                )
            )
        )
        if objects:
            unrestricted = objects.startswith("No object-src") or "*" in objects.split()
            add(
                Status.ISSUE if unrestricted else Status.OBSERVATION,
                "CSP object-src is not 'none'",
                objects,
                "Plugin and object content is not blocked by the policy.",
                "Add object-src 'none'.",
            )
        else:
            ok("CSP object-src 'none'", "object-src resolves to 'none'")

        base = every(lambda p: None if p.get("base-uri") is not None else "No base-uri directive")
        if base:
            uses_nonces = any(csp.has_nonce_or_hash(script_sources(p)) for p in enforced)
            add(
                Status.ISSUE if uses_nonces else Status.OBSERVATION,
                "CSP has no base-uri",
                base,
                "An injected <base> tag can change where relative script URLs load from"
                + (", which defeats nonce-based policies." if uses_nonces else "."),
                "Add base-uri 'none' or base-uri 'self'.",
            )

        for policy in enforced:
            if policy.source == "meta":
                ignored = [d for d in csp.META_IGNORED if d in policy.directives]
                if ignored:
                    add(
                        Status.OBSERVATION,
                        "CSP directives ignored in meta policy",
                        f"{', '.join(ignored)} set in a <meta> policy",
                        "Browsers ignore these directives when the policy is set by <meta>.",
                        "Send the policy as an HTTP header.",
                    )
            if policy.duplicates:
                add(
                    Status.OBSERVATION,
                    "CSP has duplicate directives",
                    f"Repeated: {', '.join(policy.duplicates)} (later copies are ignored)",
                    "Browsers use only the first copy of a repeated directive.",
                    "Merge the repeated directives.",
                )
        if len(enforced) > 1:
            add(
                Status.OBSERVATION,
                "Multiple enforced CSP policies",
                f"{len(enforced)} enforced policies",
                "Browsers enforce every policy, so a resource must pass all of them.",
                None,
            )
        return findings

    # Strict-Transport-Security

    def _hsts(self, ctx: TargetContext, page: Page) -> list[Finding]:
        url = page.url
        values = page.header_all("strict-transport-security")
        rep = self._reproduce(ctx, page, "strict-transport-security")
        ref = [MDN + "Strict-Transport-Security"]
        final_https = (page.final_url or url).startswith("https://")
        if not final_https:
            if values:
                return [
                    self.finding(
                        title="HSTS sent over plain HTTP",
                        status=Status.OBSERVATION,
                        affected_url=url,
                        observed=f"Strict-Transport-Security: {values[0]}",
                        why_it_matters="Browsers ignore HSTS received over HTTP.",
                        remediation="Redirect to HTTPS and send HSTS on the HTTPS responses.",
                        reproduce=rep,
                        references=ref,
                    )
                ]
            return []
        if not values:
            return [
                self.finding(
                    title="Strict-Transport-Security not set",
                    status=Status.ISSUE,
                    affected_url=url,
                    observed="Header absent",
                    expected="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    why_it_matters=(
                        "Browsers will still try plain HTTP first, which an on-path attacker "
                        "can intercept."
                    ),
                    remediation="Send Strict-Transport-Security on every HTTPS response.",
                    reproduce=rep,
                    references=ref,
                )
            ]
        findings: list[Finding] = []
        value = values[0]
        directives, problems = parse_hsts(value)
        observed = f"Strict-Transport-Security: {value}"
        if len(values) > 1:
            findings.append(
                self.finding(
                    title="Multiple HSTS headers",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=" | ".join(values),
                    why_it_matters="Browsers process only the first HSTS header.",
                    remediation="Send a single Strict-Transport-Security header.",
                    reproduce=rep,
                    references=ref,
                )
            )
        if problems:
            findings.append(
                self.finding(
                    title="HSTS header is invalid",
                    status=Status.ISSUE,
                    affected_url=url,
                    observed=f"{observed} ({'; '.join(problems)})",
                    expected="max-age=<seconds>, each directive once",
                    why_it_matters="Browsers ignore an HSTS header that breaks the syntax rules.",
                    remediation="Correct the header so each directive appears once.",
                    reproduce=rep,
                    references=ref,
                )
            )
            return findings
        max_age = int(directives["max-age"])
        if max_age == 0:
            findings.append(
                self.finding(
                    title="HSTS max-age is 0",
                    status=Status.ISSUE,
                    affected_url=url,
                    observed=observed,
                    expected="max-age=31536000 or more",
                    why_it_matters="max-age=0 tells browsers to forget the HSTS policy.",
                    remediation="Set max-age to at least 31536000.",
                    reproduce=rep,
                    references=ref,
                )
            )
        elif max_age < ONE_YEAR:
            findings.append(
                self.finding(
                    title="HSTS max-age below one year",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=f"{observed} ({max_age} seconds, about {max_age // 86400} days)",
                    expected="max-age=31536000 or more",
                    why_it_matters="The policy lapses sooner for visitors who do not return.",
                    remediation="Raise max-age to at least 31536000.",
                    reproduce=rep,
                    references=ref,
                )
            )
        else:
            findings.append(
                self.finding(
                    title="HSTS max-age",
                    status=Status.OK,
                    affected_url=url,
                    observed=observed,
                    why_it_matters="Check passed.",
                )
            )
        if "includesubdomains" not in directives:
            findings.append(
                self.finding(
                    title="HSTS without includeSubDomains",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=observed,
                    why_it_matters="Subdomains are not covered by the policy.",
                    remediation="Add includeSubDomains once every subdomain serves HTTPS.",
                    reproduce=rep,
                    references=ref,
                )
            )
        return findings

    # X-Content-Type-Options

    def _nosniff(self, ctx: TargetContext, page: Page) -> list[Finding]:
        value = page.header("x-content-type-options")
        rep = self._reproduce(ctx, page, "x-content-type-options")
        ref = [MDN + "X-Content-Type-Options"]
        if value is None:
            return [
                self.finding(
                    title="X-Content-Type-Options not set",
                    status=Status.ISSUE,
                    affected_url=page.url,
                    observed="Header absent",
                    expected="X-Content-Type-Options: nosniff",
                    why_it_matters=(
                        "Browsers may guess content types, so an uploaded or reflected file "
                        "could be treated as script or HTML."
                    ),
                    remediation="Send X-Content-Type-Options: nosniff on every response.",
                    reproduce=rep,
                    references=ref,
                )
            ]
        if value.strip().lower() != "nosniff":
            return [
                self.finding(
                    title="X-Content-Type-Options has an unexpected value",
                    status=Status.ISSUE,
                    affected_url=page.url,
                    observed=f"X-Content-Type-Options: {value}",
                    expected="X-Content-Type-Options: nosniff",
                    why_it_matters="Any value other than nosniff is ignored by browsers.",
                    remediation="Set the value to nosniff.",
                    reproduce=rep,
                    references=ref,
                )
            ]
        return [
            self.finding(
                title="X-Content-Type-Options",
                status=Status.OK,
                affected_url=page.url,
                observed="nosniff",
                why_it_matters="Check passed.",
            )
        ]

    # X-XSS-Protection

    def _xss(self, ctx: TargetContext, page: Page) -> list[Finding]:
        value = page.header("x-xss-protection")
        if value is None or value.strip() == "0":
            return [
                self.finding(
                    title="X-XSS-Protection",
                    status=Status.OK,
                    affected_url=page.url,
                    observed="Absent" if value is None else "0",
                    why_it_matters="Check passed.",
                )
            ]
        return [
            self.finding(
                title="Deprecated X-XSS-Protection filter enabled",
                status=Status.OBSERVATION,
                affected_url=page.url,
                observed=f"X-XSS-Protection: {value}",
                expected="X-XSS-Protection: 0, or the header absent",
                why_it_matters=(
                    "Modern browsers removed the XSS filter. Where it still exists it has been "
                    "used to cause information leaks. It is not a substitute for CSP."
                ),
                remediation="Set X-XSS-Protection: 0 or remove it, and rely on CSP.",
                reproduce=self._reproduce(ctx, page, "x-xss-protection"),
                references=[MDN + "X-XSS-Protection"],
            )
        ]

    # Referrer-Policy

    def _referrer(self, ctx: TargetContext, page: Page) -> list[Finding]:
        value = page.header("referrer-policy")
        rep = self._reproduce(ctx, page, "referrer-policy")
        ref = [MDN + "Referrer-Policy"]
        if value is None:
            return [
                self.finding(
                    title="Referrer-Policy not set",
                    status=Status.OBSERVATION,
                    affected_url=page.url,
                    observed="Header absent",
                    expected="Referrer-Policy: strict-origin-when-cross-origin or stricter",
                    why_it_matters=(
                        "Current browsers default to strict-origin-when-cross-origin; older "
                        "browsers may send full URLs to other sites."
                    ),
                    remediation="Set Referrer-Policy: strict-origin-when-cross-origin.",
                    reproduce=rep,
                    references=ref,
                )
            ]
        tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
        known = [t for t in tokens if t in REFERRER_VALUES]
        if not known:
            return [
                self.finding(
                    title="Referrer-Policy value not recognised",
                    status=Status.ISSUE,
                    affected_url=page.url,
                    observed=f"Referrer-Policy: {value}",
                    expected="A valid policy such as strict-origin-when-cross-origin",
                    why_it_matters="Browsers ignore unknown values and fall back to the default.",
                    remediation="Use a valid Referrer-Policy value.",
                    reproduce=rep,
                    references=ref,
                )
            ]
        effective = known[-1]
        if effective in ("unsafe-url", "no-referrer-when-downgrade"):
            return [
                self.finding(
                    title=f"Referrer-Policy {effective}",
                    status=Status.ISSUE,
                    affected_url=page.url,
                    observed=f"Referrer-Policy: {value}",
                    expected="strict-origin-when-cross-origin or stricter",
                    why_it_matters=(
                        "Full URLs, including paths and query strings, are sent to other sites."
                    ),
                    remediation="Use strict-origin-when-cross-origin, same-origin or no-referrer.",
                    reproduce=rep,
                    references=ref,
                )
            ]
        return [
            self.finding(
                title="Referrer-Policy",
                status=Status.OK,
                affected_url=page.url,
                observed=effective,
                why_it_matters="Check passed.",
            )
        ]

    def _informational(self, ctx: TargetContext, page: Page) -> Finding:
        lines = []
        for header in INFO_HEADERS:
            value = page.header(header)
            lines.append(f"{header}: {value}" if value else f"{header}: not set")
        return self.finding(
            title="Cross-origin and permissions headers",
            status=Status.OBSERVATION,
            affected_url=page.url,
            observed="\n".join(lines),
            why_it_matters="Informational. These limit browser features and cross-origin access.",
        )

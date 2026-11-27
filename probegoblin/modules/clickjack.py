"""ClickjackGoblin: framing protection on every page fetched, plus browser confirmation."""

from __future__ import annotations

from probegoblin.core import csp
from probegoblin.core.context import TargetContext
from probegoblin.core.findings import merge_across_pages
from probegoblin.core.models import Finding, ModuleResult, Page, Status
from probegoblin.core.registry import Goblin

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"


def poc_html(url: str) -> str:
    return (
        '<html><body><p>Clickjacking PoC</p><iframe src="'
        + url
        + '" width="1000" height="700" style="opacity:0.8"></iframe></body></html>'
    )


def framing_state(page: Page, policies: list[csp.Policy]) -> tuple[bool, str, list[str]]:
    """Return (frameable, summary, notes) from headers alone."""
    notes: list[str] = []
    xfo_values = [v.strip() for v in page.header_all("x-frame-options")]
    xfo_tokens = [t.strip().lower() for v in xfo_values for t in v.split(",") if t.strip()]
    header_fa = [
        p.get("frame-ancestors")
        for p in policies
        if p.enforced and p.source == "header" and p.get("frame-ancestors") is not None
    ]
    meta_fa = [p for p in policies if p.source == "meta" and p.get("frame-ancestors") is not None]
    if meta_fa:
        notes.append("frame-ancestors in a <meta> policy is ignored by browsers")
    report_only_fa = [p for p in policies if p.report_only and p.get("frame-ancestors")]
    if report_only_fa:
        notes.append("frame-ancestors in Report-Only is not enforced")

    if header_fa:
        # The most restrictive enforced policy wins.
        for sources in header_fa:
            if sources == ["'none'"] or not sources:
                return False, "CSP frame-ancestors 'none'", notes
        for sources in header_fa:
            if "*" not in sources and not any(s in ("https:", "http:") for s in sources):
                if xfo_tokens:
                    notes.append(
                        "X-Frame-Options is also set; frame-ancestors takes precedence in "
                        "modern browsers"
                    )
                return False, f"CSP frame-ancestors {' '.join(sources)}", notes
        notes.append("frame-ancestors allows any origin")
        if xfo_tokens:
            notes.append("X-Frame-Options is overridden by frame-ancestors in modern browsers")
        return True, f"CSP frame-ancestors {' '.join(header_fa[0])}", notes

    if not xfo_tokens:
        return True, "No X-Frame-Options and no CSP frame-ancestors", notes
    distinct = set(xfo_tokens)
    if len(distinct) > 1:
        notes.append(f"conflicting X-Frame-Options values ({', '.join(xfo_values)})")
        if distinct & {"deny", "sameorigin"}:
            return False, f"X-Frame-Options: {', '.join(xfo_values)} (treated as DENY)", notes
    token = xfo_tokens[0]
    if token in ("deny", "sameorigin"):
        return False, f"X-Frame-Options: {xfo_values[0]}", notes
    if token.startswith("allow-from"):
        notes.append("ALLOW-FROM is not supported by modern browsers and is ignored")
        return True, f"X-Frame-Options: {xfo_values[0]} (unsupported)", notes
    notes.append(f"invalid X-Frame-Options value {xfo_values[0]!r} is ignored")
    return True, f"X-Frame-Options: {xfo_values[0]} (invalid)", notes


class ClickjackGoblin(Goblin):
    name = "ClickjackGoblin"
    flag = "clickjack"
    prefix = "CLK"
    order = 40
    uses_browser = True
    description = "X-Frame-Options and CSP frame-ancestors on every page fetched"

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        pages = [p for p in ctx.store.html_pages() if "static" not in p.tags]
        if ctx.store.landing and ctx.store.landing not in pages and ctx.store.landing.is_html:
            pages.insert(0, ctx.store.landing)
        if not pages:
            result.not_assessed_reason = "no HTML pages returned"
            return result
        context = self._samesite_context(ctx)
        findings: list[Finding] = []
        seen_final: set[str] = set()
        for page in pages:
            final = page.final_url or page.url
            if final in seen_final:
                continue
            seen_final.add(final)
            policies = csp.page_policies(page, ctx.store.info(page))
            frameable, summary, notes = framing_state(page, policies)
            observed = summary + ("\n" + "; ".join(notes) if notes else "")
            reproduce = [
                ctx.curl(final, "-sI")
                + " | grep -iE '^(x-frame-options|content-security-policy):'",
                f"Save as poc.html and open locally: {poc_html(final)}",
            ]
            if frameable:
                sensitive = bool(page.tags & {"login", "account", "password_reset"})
                findings.append(
                    self.finding(
                        title="Page can be framed (no clickjacking protection)",
                        status=Status.ISSUE,
                        affected_url=final,
                        observed=observed,
                        expected="CSP frame-ancestors 'none' or 'self', or X-Frame-Options: DENY",
                        why_it_matters=(
                            "Another site can load this page in a hidden frame and trick a user "
                            "into clicking on it."
                            + (" The page holds sensitive actions." if sensitive else "")
                            + context
                        ),
                        remediation=(
                            "Send Content-Security-Policy: frame-ancestors 'none' (or 'self') and "
                            "X-Frame-Options: DENY for older browsers."
                        ),
                        reproduce=reproduce,
                        manual_steps=[
                            "Open the PoC and confirm the page renders inside the frame.",
                            "Check whether a single click on the framed page performs an action.",
                        ],
                        references=[MDN + "X-Frame-Options", MDN + "Content-Security-Policy"],
                    )
                )
            else:
                findings.append(
                    self.finding(
                        title="Framing blocked by headers",
                        status=Status.OK,
                        affected_url=final,
                        observed=observed,
                        why_it_matters="Check passed.",
                    )
                )
                if any("conflicting" in n or "also set" in n for n in notes):
                    findings.append(
                        self.finding(
                            title="Framing headers conflict",
                            status=Status.OBSERVATION,
                            affected_url=final,
                            observed=observed,
                            why_it_matters=(
                                "Framing is blocked, but browsers may resolve the conflict "
                                "differently."
                            ),
                            remediation="Send one consistent framing policy.",
                            reproduce=reproduce[:1],
                        )
                    )
        result.findings = merge_across_pages(findings)
        if ctx.browser is None:
            result.findings.append(
                self.not_assessed(ctx.target, "Browser framing confirmation", ctx.browser_reason)
            )
        else:
            result.findings.extend(self._confirmations(ctx, context))
        return result

    def _confirmations(self, ctx: TargetContext, context: str) -> list[Finding]:
        frames = ctx.browser.frames
        if not frames:
            return [
                self.not_assessed(
                    ctx.target, "Browser framing confirmation", "no pages were frame-tested"
                )
            ]
        out: list[Finding] = []
        for frame in frames:
            if frame.outcome == "framed":
                out.append(
                    self.finding(
                        title="Framing confirmed in Chromium",
                        status=Status.ISSUE,
                        affected_url=frame.url,
                        observed=f"Loaded in an iframe on a local page: {frame.detail}",
                        why_it_matters="The page rendered inside a frame controlled by another "
                        "origin." + context,
                        remediation="Send Content-Security-Policy: frame-ancestors 'none' (or "
                        "'self').",
                        reproduce=[f"Save as poc.html and open locally: {poc_html(frame.url)}"],
                        manual_steps=["Open the PoC in a current browser and confirm it renders."],
                    )
                )
            elif frame.outcome in ("blocked", "broke out"):
                out.append(
                    self.finding(
                        title=f"Framing {frame.outcome} in Chromium",
                        status=Status.OK,
                        affected_url=frame.url,
                        observed=frame.detail,
                        why_it_matters="Check passed.",
                    )
                )
            else:
                out.append(
                    self.not_assessed(frame.url, "Browser framing confirmation", frame.detail)
                )
        return out

    @staticmethod
    def _samesite_context(ctx: TargetContext) -> str:
        sessions = ctx.shared.get("session_cookies") or []
        if not sessions:
            return ""
        cookie = sessions[0]
        value = (cookie.samesite or "").lower()
        if value in ("lax", "strict", ""):
            shown = (
                f"has SameSite={cookie.samesite}"
                if cookie.samesite
                else "has no SameSite attribute (Chrome treats it as Lax)"
            )
            return (
                f" Session cookie {cookie.name} {shown}, so in modern browsers the framed page "
                "would usually load without the user's session, making authenticated "
                "clickjacking unlikely."
            )
        return (
            f" Session cookie {cookie.name} has SameSite=None, so the framed page loads with "
            "the user's session."
        )

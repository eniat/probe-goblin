"""CookieGoblin: assesses every cookie the target set, one by one, with purpose in mind."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from probegoblin.core import cookies as cookielib
from probegoblin.core.context import TargetContext
from probegoblin.core.models import Finding, ModuleResult, Status, Table
from probegoblin.core.registry import Goblin

MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"
SENSITIVE = (cookielib.SESSION, cookielib.CSRF, cookielib.UNKNOWN)


@dataclass
class SeenCookie:
    cookie: cookielib.SetCookie
    urls: list[str] = field(default_factory=list)
    variants: list[cookielib.SetCookie] = field(default_factory=list)

    @property
    def purpose(self) -> str:
        return cookielib.purpose(self.cookie.name)


def collect(ctx: TargetContext) -> dict[str, SeenCookie]:
    seen: dict[str, SeenCookie] = {}
    for page in ctx.store.all_pages():
        for hop in page.chain:
            for raw in hop.header_all("set-cookie"):
                cookie = cookielib.parse_set_cookie(raw)
                if cookie is None:
                    continue
                cookie.source_url = hop.url
                entry = seen.get(cookie.name)
                if entry is None:
                    seen[cookie.name] = SeenCookie(cookie, [hop.url], [cookie])
                    continue
                if hop.url not in entry.urls:
                    entry.urls.append(hop.url)
                if all(v.signature() != cookie.signature() for v in entry.variants):
                    entry.variants.append(cookie)
    for cookie in getattr(ctx.browser, "cookies", None) or []:
        if cookie.name not in seen:
            seen[cookie.name] = SeenCookie(cookie, [cookie.source_url], [cookie])
    return seen


def lifetime(cookie: cookielib.SetCookie) -> str:
    if "max-age" in cookie.attrs:
        value = cookie.attrs["max-age"]
        if value.lstrip("-").isdigit():
            seconds = int(value)
            if seconds <= 0:
                return "expired (deletes cookie)"
            if seconds >= 86400:
                return f"{seconds // 86400} days"
            return f"{seconds // 3600} h" if seconds >= 3600 else f"{seconds} s"
        return f"Max-Age={value}"
    if "expires" in cookie.attrs:
        return f"until {cookie.attrs['expires']}"
    return "session"


class CookieGoblin(Goblin):
    name = "CookieGoblin"
    flag = "cookies"
    prefix = "COO"
    order = 30
    uses_browser = True
    description = "Secure, HttpOnly, SameSite, lifetime, scope and prefix rules for each cookie"

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        seen = collect(ctx)
        login = ctx.store.tagged("login", ok_only=False)
        login_url = login[0].url if login else ctx.target
        result.findings.append(
            self.finding(
                title="Cookies issued after login not assessed",
                status=Status.MANUAL_CHECK,
                affected_url=login_url,
                observed="Only cookies set before authentication were seen",
                why_it_matters=(
                    "Session cookies are often reissued at login with different attributes."
                ),
                reproduce=[
                    ctx.curl(login_url, "-s", "-o /dev/null", "-D -") + " | grep -i set-cookie"
                ],
                manual_steps=[
                    "Log in through Burp and inspect every Set-Cookie on the login response "
                    "and the next few responses.",
                    "Check the session cookie is replaced at login (no session fixation).",
                    "Check Secure, HttpOnly and SameSite on the post-login session cookie.",
                ],
            )
        )
        if not seen:
            result.not_assessed_reason = "no cookies returned"
            return result
        sessions = []
        rows = []
        for entry in seen.values():
            cookie = entry.cookie
            purpose = entry.purpose
            if purpose == cookielib.SESSION:
                sessions.append(cookie)
            rows.append(
                [
                    cookie.name,
                    purpose,
                    "yes" if cookie.secure else "no",
                    "yes" if cookie.httponly else "no",
                    cookie.samesite or "-",
                    lifetime(cookie),
                    cookie.domain or "host only",
                    cookie.path or "-",
                    "browser" if cookie.from_browser else "Set-Cookie",
                ]
            )
            result.findings.extend(self._assess(ctx, entry))
        result.tables.append(
            Table(
                title="Cookies",
                columns=[
                    "Name",
                    "Purpose",
                    "Secure",
                    "HttpOnly",
                    "SameSite",
                    "Lifetime",
                    "Domain",
                    "Path",
                    "Set by",
                ],
                rows=rows,
            )
        )
        ctx.shared["session_cookies"] = sessions
        return result

    def _make(
        self,
        ctx: TargetContext,
        entry: SeenCookie,
        status: Status,
        title: str,
        why: str,
        fix: str | None,
        expected: str | None = None,
    ) -> Finding:
        cookie = entry.cookie
        url = cookie.source_url
        observed = f"{_redacted(cookie)} ({entry.purpose} cookie)"
        if len(entry.urls) > 1:
            observed += f"\nSet on: {', '.join(entry.urls[:5])}"
        reproduce = []
        if not cookie.from_browser:
            pattern = re.escape(cookie.name).replace("'", "")
            reproduce.append(
                ctx.curl(url, "-s", "-o /dev/null", "-D -") + f" | grep -i 'set-cookie: {pattern}='"
            )
        else:
            reproduce.append(
                f"Open {url} in a browser, then DevTools > Application > Cookies > {cookie.name}"
            )
        return self.finding(
            title=title,
            status=status,
            affected_url=url,
            observed=observed,
            expected=expected,
            why_it_matters=why,
            remediation=fix,
            reproduce=reproduce,
            references=[MDN],
        )

    def _assess(self, ctx: TargetContext, entry: SeenCookie) -> list[Finding]:
        cookie = entry.cookie
        purpose = entry.purpose
        name = cookie.name
        out: list[Finding] = []
        sensitive = purpose in SENSITIVE
        https = httpx.URL(cookie.source_url).scheme == "https"
        checks = 0

        if https and not cookie.secure:
            out.append(
                self._make(
                    ctx,
                    entry,
                    Status.ISSUE if sensitive else Status.OBSERVATION,
                    f"Cookie {name} without Secure",
                    "The browser will also send it over plain HTTP, where it can be read in "
                    "transit." + ("" if sensitive else " Low impact for this kind of cookie."),
                    "Add the Secure attribute.",
                    "Secure",
                )
            )
        else:
            checks += 1

        if not cookie.httponly:
            if purpose == cookielib.SESSION:
                out.append(
                    self._make(
                        ctx,
                        entry,
                        Status.ISSUE,
                        f"Session cookie {name} without HttpOnly",
                        "Script on the page, including injected script, can read the session "
                        "cookie.",
                        "Add the HttpOnly attribute.",
                        "HttpOnly",
                    )
                )
            elif purpose == cookielib.UNKNOWN:
                out.append(
                    self._make(
                        ctx,
                        entry,
                        Status.OBSERVATION,
                        f"Cookie {name} without HttpOnly",
                        "Readable by script. Matters only if the cookie holds something "
                        "sensitive; its purpose could not be determined.",
                        "Add HttpOnly unless client-side script needs to read it.",
                    )
                )
            else:
                checks += 1
        else:
            checks += 1

        samesite = cookie.samesite
        if samesite is not None and samesite.lower() not in ("strict", "lax", "none"):
            out.append(
                self._make(
                    ctx,
                    entry,
                    Status.ISSUE,
                    f"Cookie {name} has an invalid SameSite value",
                    "Browsers treat an unknown value as if SameSite were absent.",
                    "Use Strict, Lax or None.",
                    "SameSite=Strict or SameSite=Lax",
                )
            )
        elif samesite is not None and samesite.lower() == "none" and not cookie.secure:
            out.append(
                self._make(
                    ctx,
                    entry,
                    Status.ISSUE,
                    f"Cookie {name} has SameSite=None without Secure",
                    "Current browsers reject SameSite=None cookies that are not Secure.",
                    "Add Secure, or use SameSite=Lax.",
                    "SameSite=None; Secure",
                )
            )
        elif samesite is not None and samesite.lower() == "none" and sensitive:
            out.append(
                self._make(
                    ctx,
                    entry,
                    Status.OBSERVATION,
                    f"Cookie {name} sent on cross-site requests (SameSite=None)",
                    "Sent with cross-site requests, so CSRF protection must not rely on "
                    "SameSite.",
                    "Use SameSite=Lax or Strict unless cross-site use is required.",
                )
            )
        elif samesite is None and purpose in (cookielib.SESSION, cookielib.CSRF):
            out.append(
                self._make(
                    ctx,
                    entry,
                    Status.OBSERVATION,
                    f"Cookie {name} without SameSite",
                    "Chrome treats it as Lax; Firefox and Safari do not apply Lax by "
                    "default, so cross-site requests may carry it.",
                    "Set SameSite=Lax or Strict explicitly.",
                    "SameSite=Lax or SameSite=Strict",
                )
            )
        else:
            checks += 1

        if purpose == cookielib.SESSION and cookie.persistent:
            out.append(
                self._make(
                    ctx,
                    entry,
                    Status.OBSERVATION,
                    f"Session cookie {name} is persistent",
                    f"It survives browser restarts ({lifetime(cookie)}).",
                    "Use a session cookie (no Expires or Max-Age) unless 'remember me' is wanted.",
                )
            )

        domain = (cookie.domain or "").lstrip(".").lower()
        host = httpx.URL(cookie.source_url).host.lower()
        if domain and domain != host and sensitive:
            out.append(
                self._make(
                    ctx,
                    entry,
                    Status.OBSERVATION,
                    f"Cookie {name} scoped to the parent domain",
                    f"Domain={cookie.domain} sends it to every subdomain of {domain}, so any "
                    "of them can read it.",
                    "Remove the Domain attribute so the cookie is host-only.",
                )
            )

        lowered = name.lower()
        problems = []
        if lowered.startswith("__host-"):
            if not cookie.secure:
                problems.append("no Secure")
            if cookie.domain:
                problems.append("Domain set")
            if (cookie.path or "") != "/":
                problems.append("Path is not /")
        elif lowered.startswith("__secure-") and not cookie.secure:
            problems.append("no Secure")
        if problems:
            out.append(
                self._make(
                    ctx,
                    entry,
                    Status.ISSUE,
                    f"Cookie {name} breaks its prefix rules",
                    f"Browsers reject this cookie ({', '.join(problems)}).",
                    "Set the attributes the prefix requires.",
                )
            )

        if len(entry.variants) > 1:
            versions = " | ".join(_redacted(v) for v in entry.variants[:3])
            out.append(
                self._make(
                    ctx,
                    entry,
                    Status.OBSERVATION,
                    f"Cookie {name} set with different attributes",
                    "The same cookie is set differently on different responses: " + versions,
                    "Set the cookie with the same attributes everywhere.",
                )
            )

        for _ in range(checks):
            out.append(
                self.finding(
                    title=f"Cookie {name}",
                    status=Status.OK,
                    affected_url=cookie.source_url,
                    why_it_matters="Check passed.",
                )
            )
        return out


def _redacted(cookie: cookielib.SetCookie) -> str:
    value = cookie.value
    shown = value[:4] + "..." if len(value) > 4 else value
    attrs = "; ".join(f"{k}={v}" if v else k for k, v in cookie.attrs.items())
    return f"{cookie.name}={shown}" + (f"; {attrs}" if attrs else "")

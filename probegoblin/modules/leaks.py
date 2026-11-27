"""LeakGoblin: secrets, endpoints, buckets, internal hosts and emails in collected content."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import httpx

from probegoblin.core.context import TargetContext
from probegoblin.core.models import Finding, ModuleResult, Status, Table
from probegoblin.core.registry import Goblin
from probegoblin.core.secrets import find_secrets, grep_for, mask

MAX_ENDPOINTS = 60
ENDPOINT = re.compile(
    r"""["'`](/(?:api|v\d+|graphql|rest|internal|admin|auth|oauth2?|user|users|account|"""
    r"""accounts|private|backend|service|services|rpc|ajax)(?:/[\w\-.{}:$%]*)*/?)(?:\?[^"'`\s]*)?["'`]""",
    re.I,
)
ABSOLUTE = re.compile(r"""["'`](https?://[\w.-]+(?::\d+)?(?:/[^"'`\s<>]*)?)["'`]""")
BUCKETS = [
    (
        "S3 bucket",
        re.compile(
            r"\b([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com\b"
        ),
    ),
    (
        "S3 bucket",
        re.compile(r"\bs3[.-](?:[a-z0-9-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\b"),
    ),
    ("S3 bucket", re.compile(r"\bs3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\b")),
    (
        "Azure blob container",
        re.compile(r"\b([a-z0-9]{3,24}\.blob\.core\.windows\.net(?:/[a-z0-9-]{3,63})?)", re.I),
    ),
    (
        "Google Cloud Storage bucket",
        re.compile(r"\bstorage\.googleapis\.com/([a-z0-9][\w.-]{1,61}[a-z0-9])\b"),
    ),
    (
        "Google Cloud Storage bucket",
        re.compile(r"\b([a-z0-9][\w.-]{1,61}[a-z0-9])\.storage\.googleapis\.com\b"),
    ),
    ("Google Cloud Storage bucket", re.compile(r"\bgs://([a-z0-9][\w.-]{1,61}[a-z0-9])\b")),
]
PRIVATE_IP = re.compile(r"""(?:://|@|["'`\s=:])((?:\d{1,3}\.){3}\d{1,3})(?=[:/"'`\s,;)]|$)""")
INTERNAL_HOST = re.compile(
    r"\b((?:[a-z0-9-]+\.)+(?:internal|local|corp|lan|intranet|localdomain|intra|private))\b", re.I
)
LOCALHOST = re.compile(r"\b(localhost:\d{2,5})\b")
EMAIL = re.compile(r"\b[\w.+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
EMAIL_SKIP = re.compile(
    r"@(?:\d+x\.|example\.(?:com|org|net)|sentry\.io|domain\.com|email\.com|test\.com)|"
    r"\.(png|jpe?g|gif|svg|webp|css|js)$",
    re.I,
)
BUCKET_GREP = (
    " | grep -oiE '[a-z0-9.-]+\\.(s3[.-][a-z0-9.-]*amazonaws\\.com|"
    "blob\\.core\\.windows\\.net|storage\\.googleapis\\.com)'"
)
INTERNAL_GREP = " | grep -oE '(10|172|192\\.168)\\.[0-9.]+|[a-z0-9.-]+\\.(internal|local|corp|lan)'"
LOCAL_SUFFIX_FALSE = {"window.local", "this.local", "e.local", "t.local"}


@dataclass
class Source:
    url: str
    kind: str  # "JavaScript", "HTML", "headers"
    text: str


def sources(ctx: TargetContext) -> list[Source]:
    out: list[Source] = []
    seen: set[str] = set()
    for page in ctx.store.js:
        out.append(Source(page.final_url or page.url, "JavaScript", page.text))
        seen.add(page.url)
    for page in ctx.store.all_pages():
        if page.status is None:
            continue
        headers = "\n".join(f"{k}: {v}" for k, v in page.headers if k.lower() != "set-cookie")
        out.append(Source(page.final_url or page.url, "headers", headers))
        if page.url in seen or not page.body or page.soft_404:
            continue
        if "static" in page.tags and not page.content_type.endswith("javascript"):
            continue
        out.append(
            Source(page.final_url or page.url, "HTML" if page.is_html else "response", page.text)
        )
    browser = getattr(ctx, "browser", None)
    if browser is not None:
        for script in browser.scripts:
            if script.url in seen:
                continue
            seen.add(script.url)
            same = ctx.client.scope.is_target(httpx.URL(script.url))
            kind = "JavaScript" if same else "third-party JavaScript"
            out.append(Source(script.url, kind, script.body))
    return out


def _line(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _private(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


class LeakGoblin(Goblin):
    name = "LeakGoblin"
    flag = "leaks"
    prefix = "LEK"
    order = 130
    uses_browser = True
    description = (
        "Secrets, JS endpoints, cloud buckets, internal hosts and emails (no extra requests)"
    )

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        items = sources(ctx)
        result.findings.extend(self._secrets(ctx, items))
        endpoints = self._endpoints(ctx, items)
        if endpoints:
            result.tables.append(
                Table(
                    title="Endpoints referenced in JavaScript and HTML (not requested)",
                    columns=["Endpoint", "Found in"],
                    rows=endpoints[:MAX_ENDPOINTS],
                )
            )
            more = len(endpoints) - MAX_ENDPOINTS
            result.findings.append(
                self.finding(
                    title=f"{len(endpoints)} endpoints referenced in client code",
                    status=Status.MANUAL_CHECK,
                    affected_url=endpoints[0][1].split(" ")[0],
                    observed="See the table above"
                    + (f" ({more} more not shown)" if more > 0 else ""),
                    why_it_matters="Endpoints in client code are a test list; some may lack "
                    "access control.",
                    reproduce=[
                        ctx.curl(endpoints[0][1].split(" ")[0], "-s")
                        + " | grep -oE '[\"'\\''](/api[^\"'\\'']*)' | sort -u"
                    ],
                    manual_steps=[
                        "Request each endpoint through Burp, with and without a session, and "
                        "check authorisation."
                    ],
                )
            )
        result.findings.extend(self._grouped(ctx, items))
        if ctx.browser is None and ctx.store.third_party_scripts:  # bodies come from the browser
            result.findings.append(
                self.not_assessed(
                    ctx.target,
                    "Third-party JavaScript content",
                    f"{ctx.browser_reason}; only same-host files were scanned",
                )
            )
        if not result.findings:
            result.findings.append(
                self.finding(
                    title="Secrets and leaks",
                    status=Status.OK,
                    affected_url=ctx.target,
                    observed=f"{len(items)} responses and files scanned, nothing found",
                    why_it_matters="Check passed.",
                )
            )
        return result

    def _secrets(self, ctx: TargetContext, items: list[Source]) -> list[Finding]:
        out: list[Finding] = []
        seen: set[str] = set()
        for source in items:
            for hit in find_secrets(source.text):
                if hit.value in seen:
                    continue
                seen.add(hit.value)
                why = {
                    Status.ISSUE: "A live credential in content any visitor can download.",
                    Status.MANUAL_CHECK: hit.note,
                }.get(hit.status, hit.note)
                reproduce = [ctx.curl(source.url, "-s") + f" | grep -oP '{grep_for(hit.kind)}'"]
                if source.kind == "headers":
                    reproduce = [
                        ctx.curl(source.url, "-sI") + f" | grep -oP '{grep_for(hit.kind)}'"
                    ]
                out.append(
                    self.finding(
                        title=f"{hit.kind} in {source.kind}",
                        status=hit.status,
                        affected_url=source.url,
                        observed=f"{hit.kind} {mask(hit.value)} at line {hit.line}",
                        why_it_matters=why or "Possible credential in client content.",
                        remediation=(
                            "Remove it from client content and rotate it."
                            if hit.status == Status.ISSUE
                            else "Confirm whether the value is a real credential."
                        ),
                        reproduce=reproduce,
                        manual_steps=(
                            [
                                "Confirm the value in Burp. Do not use the credential unless the "
                                "engagement allows it.",
                            ]
                            if hit.status == Status.ISSUE
                            else [
                                "Check what the value is and whether it grants access to anything.",
                            ]
                        ),
                    )
                )
        return out

    def _endpoints(self, ctx: TargetContext, items: list[Source]) -> list[list[str]]:
        found: dict[str, str] = {}
        for source in items:
            if source.kind == "headers":
                continue
            for match in ENDPOINT.finditer(source.text):
                path = match.group(1)
                found.setdefault(path, f"{source.url} line {_line(source.text, match.start())}")
            for match in ABSOLUTE.finditer(source.text):
                url = match.group(1)
                try:
                    parsed = httpx.URL(url)
                except (httpx.InvalidURL, ValueError):
                    continue
                if parsed.host == ctx.host and re.search(r"/(api|v\d|graphql|rest)\b", parsed.path):
                    found.setdefault(url, f"{source.url} line {_line(source.text, match.start())}")
        return [[endpoint, where] for endpoint, where in sorted(found.items())]

    def _grouped(self, ctx: TargetContext, items: list[Source]) -> list[Finding]:
        buckets: dict[str, tuple[str, str]] = {}
        internal: dict[str, str] = {}
        emails: dict[str, str] = {}
        own = {ctx.host, *ctx.ips}
        for source in items:
            text = source.text
            for kind, pattern in BUCKETS:
                for match in pattern.finditer(text):
                    buckets.setdefault(f"{kind}: {match.group(1)}", (source.url, kind))
            for match in PRIVATE_IP.finditer(text):
                ip = match.group(1)
                if _private(ip) and not ip.startswith("0.") and ip not in own:
                    internal.setdefault(f"private IP {ip}", source.url)
            for match in INTERNAL_HOST.finditer(text):
                host = match.group(1).lower()
                if host not in LOCAL_SUFFIX_FALSE and not host.startswith(("www.", "e.", "t.")):
                    internal.setdefault(f"internal host {host}", source.url)
            for match in LOCALHOST.finditer(text):
                internal.setdefault(f"{match.group(1)}", source.url)
            if source.kind != "headers":
                for match in EMAIL.finditer(text):
                    email = match.group(0)
                    if not EMAIL_SKIP.search(email):
                        emails.setdefault(email.lower(), source.url)
        out: list[Finding] = []
        if buckets:
            first_url = next(iter(buckets.values()))[0]
            out.append(
                self.finding(
                    title="Cloud storage references",
                    status=Status.OBSERVATION,
                    affected_url=first_url,
                    observed="\n".join(
                        f"{name} (in {url})" for name, (url, _) in list(buckets.items())[:15]
                    ),
                    why_it_matters="Named buckets can be checked for public listing or write "
                    "access. They were not contacted.",
                    reproduce=[ctx.curl(first_url, "-s") + BUCKET_GREP],
                    manual_steps=[
                        "Check each bucket for anonymous list and read access, only if the "
                        "bucket is in scope.",
                    ],
                )
            )
        if internal:
            first_url = next(iter(internal.values()))
            out.append(
                self.finding(
                    title="Internal hostnames or private addresses",
                    status=Status.OBSERVATION,
                    affected_url=first_url,
                    observed="\n".join(
                        f"{name} (in {url})" for name, url in list(internal.items())[:15]
                    ),
                    why_it_matters="Reveals internal network layout or backend services.",
                    remediation="Remove internal references from public content.",
                    reproduce=[ctx.curl(first_url, "-s") + INTERNAL_GREP],
                )
            )
        if emails:
            first_url = next(iter(emails.values()))
            out.append(
                self.finding(
                    title="Email addresses",
                    status=Status.OBSERVATION,
                    affected_url=first_url,
                    observed="\n".join(
                        f"{email} (in {url})" for email, url in list(emails.items())[:15]
                    ),
                    why_it_matters="Shows username formats and phishing scope. Often intended.",
                )
            )
        return out

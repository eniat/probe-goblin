"""TechnologyGoblin: fingerprints the stack from data already collected."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import tempfile
import tomllib
from functools import lru_cache
from pathlib import Path

import mmh3

from probegoblin.core import datafiles
from probegoblin.core.context import TargetContext, Technology
from probegoblin.core.external import INSTALL_HINTS, find_tool, run_tool
from probegoblin.core.findings import merge_across_pages
from probegoblin.core.models import Finding, ModuleResult, Status, Table
from probegoblin.core.registry import Goblin
from probegoblin.intelligence import nvd
from probegoblin.intelligence.cache import IntelClient, SourceError
from probegoblin.modules import _fingerprints as fingerprints

MAX_NVD_LOOKUPS = 10
VERSION_IN_VALUE = re.compile(r"\d+\.\d+")

# Header name to (what it discloses, whether a version is expected).
DISCLOSURE_HEADERS = {
    "server": "server software",
    "x-powered-by": "application framework or language",
    "x-aspnet-version": "ASP.NET runtime version",
    "x-aspnetmvc-version": "ASP.NET MVC version",
    "x-generator": "site generator or CMS",
    "x-powered-cms": "CMS",
    "x-drupal-cache": "Drupal page cache",
    "x-drupal-dynamic-cache": "Drupal dynamic page cache",
    "x-mod-pagespeed": "mod_pagespeed version",
    "x-page-speed": "PageSpeed version",
    "x-backend-server": "backend server name",
    "x-server": "server name",
    "x-app-version": "application version",
    "x-application-version": "application version",
    "x-version": "application version",
    "liferay-portal": "Liferay version",
}
DEBUG_HEADERS = {
    "x-debug-token": "Symfony profiler token",
    "x-debug-token-link": "Symfony profiler link",
}
TIMING_HEADERS = {
    "x-runtime": "server processing time",
    "server-timing": "server timing breakdown",
    "x-envoy-upstream-service-time": "upstream service time",
}
WHATWEB_NOISE = {
    "Country",
    "IP",
    "Title",
    "Script",
    "HTML5",
    "UncommonHeaders",
    "Cookies",
    "HttpOnly",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "RedirectLocation",
    "Meta-Refresh-Redirect",
    "Email",
    "Frame",
    "PasswordField",
    "Object",
    "X-UA-Compatible",
    "Content-Security-Policy",
    "Access-Control-Allow-Methods",
}


@lru_cache(maxsize=1)
def favicon_db() -> dict[int, dict[str, str]]:
    text = datafiles.read_text("favicons.toml")
    return {int(entry["hash"]): entry for entry in tomllib.loads(text).get("favicon", [])}


def favicon_hash(data: bytes) -> int:
    """Shodan-style favicon hash: mmh3 of base64 with a newline every 76 characters."""
    return mmh3.hash(base64.encodebytes(data))


def parse_whatweb(text: str) -> list[dict]:
    """whatweb --log-json output: a JSON array, or one object per line in some versions."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        pass
    entries = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if line in ("", "[", "]"):
            continue
        entries.append(json.loads(line))
    return entries


class TechnologyGoblin(Goblin):
    name = "TechnologyGoblin"
    flag = "tech"
    prefix = "TEC"
    order = 10
    uses_browser = True
    description = "Fingerprints server, frameworks, CMS, CDN and integrations; version headers"

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        ev = fingerprints.collect(ctx.store, ctx.browser)
        detections, browser_needed = await asyncio.to_thread(fingerprints.match, ev)
        rows = []
        for det in detections:
            cats = fingerprints.categories_for(det.name)
            ctx.tech.append(
                Technology(
                    name=det.name,
                    version=det.version,
                    categories=cats,
                    sources=det.evidence or [f"implied by {det.implied_by}"],
                    cpe=fingerprints.cpe_for(det.name),
                )
            )
            evidence = ", ".join(det.evidence) if det.evidence else f"implied by {det.implied_by}"
            rows.append([det.name, det.version or "-", ", ".join(cats[:2]) or "-", evidence])
        if rows:
            result.tables.append(
                Table(
                    title="Technologies (webappanalyzer fingerprints)",
                    columns=["Technology", "Version", "Category", "Evidence"],
                    rows=rows,
                )
            )
        if browser_needed and ctx.browser is None:
            result.findings.append(
                self.not_assessed(
                    ctx.target,
                    "JavaScript and DOM fingerprints",
                    f"{ctx.browser_reason}; fingerprints that need the live page were skipped",
                )
            )
        result.findings.extend(await self._server_cves(ctx))
        result.findings.extend(self._headers(ctx))
        result.findings.extend(self._favicon(ctx))
        table, finding = await self._whatweb(ctx)
        if table:
            result.tables.append(table)
        if finding:
            result.findings.append(finding)
        return result

    async def _server_cves(self, ctx: TargetContext) -> list[Finding]:
        versioned = [
            t
            for t in ctx.tech
            if t.cpe and t.version and not any("JavaScript" in c for c in t.categories)
        ][
            :MAX_NVD_LOOKUPS
        ]  # JS libraries are looked up by JSGoblin
        if not versioned:
            return []
        if nvd.api_key() is None:
            names = ", ".join(t.label for t in versioned)
            return [
                self.not_assessed(
                    ctx.target,
                    "CVE lookup for server-side versions",
                    f"NVD_API_KEY not set, so {names} were not checked",
                )
            ]
        out: list[Finding] = []
        landing = ctx.store.landing
        async with IntelClient() as client:
            for tech in versioned:
                try:
                    cves = await nvd.lookup(client, tech.cpe, tech.version)
                except SourceError as exc:
                    out.append(
                        self.not_assessed(ctx.target, f"NVD lookup for {tech.label}", str(exc))
                    )
                    continue
                if not cves:
                    continue
                cves.sort(key=lambda c: -(c.score or 0))
                lines = [
                    f"{c.id}  CVSS {c.score if c.score is not None else '-'}"
                    + (f" {c.severity.title()}" if c.severity else "")
                    + (f"\n    {c.summary}" if c.summary else "")
                    for c in cves[:10]
                ]
                if len(cves) > 10:
                    lines.append(f"and {len(cves) - 10} more")
                out.append(
                    self.finding(
                        title=f"{tech.label}: {len(cves)} CVEs by version (unconfirmed)",
                        status=Status.MANUAL_CHECK,
                        affected_url=landing.final_url or landing.url,
                        observed=f"Version from {', '.join(tech.sources)}\n" + "\n".join(lines),
                        why_it_matters=(
                            "Version-based, unconfirmed, distro backports possible. The version "
                            "string may not reflect patches applied by the vendor or distribution."
                        ),
                        reproduce=[ctx.curl(landing.final_url or landing.url, "-sI")],
                        manual_steps=[
                            "Confirm the real version and patch level with the client before "
                            "reporting any of these CVEs."
                        ],
                        references=[f"https://nvd.nist.gov/vuln/detail/{c.id}" for c in cves[:3]],
                    )
                )
        return out

    def _headers(self, ctx: TargetContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for page in ctx.store.all_pages():
            if page.status is None or page.source == "baseline":
                continue
            for hop in page.chain:
                for key, value in hop.headers:
                    lower = key.lower()
                    marker = (lower, value, hop.url)
                    if marker in seen:
                        continue
                    seen.add(marker)
                    finding = self._header_finding(ctx, hop.url, key, lower, value)
                    if finding:
                        findings.append(finding)
        return merge_across_pages(findings)

    def _header_finding(
        self, ctx: TargetContext, url: str, key: str, lower: str, value: str
    ) -> Finding | None:
        reproduce = [ctx.curl(url, "-sI") + f" | grep -i '^{key}:'"]
        fix = f"Remove the {key} header, or strip the version from it, at the web server or proxy."
        if lower in DEBUG_HEADERS:
            return self.finding(
                title=f"{key} header present",
                status=Status.ISSUE,
                affected_url=url,
                observed=f"{key}: {value}",
                expected="No debug headers in production responses",
                why_it_matters=(
                    f"The {DEBUG_HEADERS[lower]} is only sent when the Symfony profiler is on, "
                    "which records request data such as headers, cookies and queries."
                ),
                remediation="Disable the profiler and debug mode in production (APP_ENV=prod).",
                reproduce=reproduce,
            )
        if lower in TIMING_HEADERS:
            return self.finding(
                title=f"{key} header discloses {TIMING_HEADERS[lower]}",
                status=Status.OBSERVATION,
                affected_url=url,
                observed=f"{key}: {value}",
                why_it_matters="Timing detail can help an attacker compare code paths.",
                remediation=f"Remove {key} from production responses if it is not needed.",
                reproduce=reproduce,
            )
        if lower not in DISCLOSURE_HEADERS:
            return None
        if VERSION_IN_VALUE.search(value):
            return self.finding(
                title=f"Version disclosed in {key} header",
                status=Status.ISSUE,
                affected_url=url,
                observed=f"{key}: {value}",
                expected=f"No version in {key}",
                why_it_matters=(
                    f"The exact {DISCLOSURE_HEADERS[lower]} lets an attacker look up known "
                    "vulnerabilities without probing."
                ),
                remediation=fix,
                reproduce=reproduce,
            )
        return self.finding(
            title=f"{key} header names the {DISCLOSURE_HEADERS[lower]}",
            status=Status.OBSERVATION,
            affected_url=url,
            observed=f"{key}: {value}",
            why_it_matters="Names the product without a version. Useful for fingerprinting only.",
            remediation=fix,
            reproduce=reproduce,
        )

    def _favicon(self, ctx: TargetContext) -> list[Finding]:
        page = ctx.store.favicon
        if page is None:
            return [self.not_assessed(ctx.target, "Favicon hash", "no favicon returned")]
        value = favicon_hash(page.body)
        ctx.summary["favicon_hash"] = value
        url = page.final_url or page.url
        match = favicon_db().get(value)
        reproduce = [
            ctx.curl(url, "-s")
            + ' | python3 -c "import sys,base64,mmh3;'
            + 'print(mmh3.hash(base64.encodebytes(sys.stdin.buffer.read())))"'
        ]
        if match:
            ctx.tech.append(Technology(name=match["product"], sources=["favicon hash"]))
            return [
                self.finding(
                    title=f"Favicon matches the default {match['product']} favicon",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=f"mmh3 {value}, the favicon shipped with {match['product']}",
                    why_it_matters="Identifies the product even when headers are stripped.",
                    reproduce=reproduce,
                    manual_steps=[f"Search Shodan for http.favicon.hash:{value}"],
                )
            ]
        return [
            self.finding(
                title="Favicon hash",
                status=Status.OBSERVATION,
                affected_url=url,
                observed=f"mmh3 {value}, no match in the bundled favicon list",
                why_it_matters="The hash can be searched to find the product or related hosts.",
                reproduce=reproduce,
                manual_steps=[f"Search Shodan for http.favicon.hash:{value}"],
            )
        ]

    async def _whatweb(self, ctx: TargetContext) -> tuple[Table | None, Finding | None]:
        title = "whatweb second opinion"
        path = find_tool("whatweb")
        if path is None:
            hint = INSTALL_HINTS["whatweb"]
            return None, self.not_assessed(ctx.target, title, f"whatweb not installed ({hint})")
        if ctx.settings.pinned_ip:
            reason = "whatweb cannot be pinned to --ip, so it would test a different server"
            return None, self.not_assessed(ctx.target, title, reason)
        with tempfile.TemporaryDirectory(prefix="probegoblin-") as tmp:
            log = Path(tmp) / "whatweb.json"
            argv = [
                path,
                "-a",
                "1",
                "--follow-redirect=never",
                "--color=never",
                "-q",
                "--no-errors",
                f"--log-json={log}",
                "-U",
                ctx.settings.user_agent,
            ]
            if ctx.settings.cookie:
                argv += ["-c", ctx.settings.cookie]
            for name, value in {**ctx.settings.extra_headers, **ctx.settings.headers}.items():
                argv += ["-H", f"{name}: {value}"]
            argv.append(ctx.target)
            limit = ctx.settings.tool_limits.whatweb
            try:
                run = await run_tool(argv, limit)
            except OSError as exc:
                return None, self.not_assessed(ctx.target, title, f"whatweb failed to start: {exc}")
            if run.timed_out:
                return None, self.not_assessed(ctx.target, title, "timed out")
            try:
                entries = parse_whatweb(log.read_text("utf-8") if log.exists() else "")
            except (json.JSONDecodeError, OSError):
                entries = None
        if not entries:
            if run.returncode:
                lines = [ln for ln in run.stderr.strip().splitlines() if ln.strip()]
                first = re.sub(r"^<[^>]+>:\d+:in `[^']*': ", "", lines[0] if lines else "no output")
                first = first[:160]
                reason = f"whatweb exited with code {run.returncode}: {first}"
            else:
                reason = "could not parse whatweb output"
            return None, self.not_assessed(ctx.target, title, reason)
        rows = []
        for entry in entries:
            for plugin, data in (entry.get("plugins") or {}).items():
                if plugin in WHATWEB_NOISE or not isinstance(data, dict):
                    continue
                version = ", ".join(map(str, data.get("version", []))) or "-"
                detail = ", ".join(map(str, data.get("string", []) + data.get("module", [])))
                rows.append([plugin, version, detail or "-"])
        if not rows:
            return None, None
        return Table(title=title, columns=["Plugin", "Version", "Detail"], rows=rows), None

"""JSGoblin: JavaScript library versions from the live page and from file content, with
latest version, end-of-life status and known vulnerabilities."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from probegoblin.core import jsruntime
from probegoblin.core.context import TargetContext
from probegoblin.core.models import Finding, ModuleResult, Status, Table
from probegoblin.core.registry import Goblin
from probegoblin.intelligence import lookup, versions
from probegoblin.intelligence.cache import IntelClient
from probegoblin.modules import _retire

MAX_CVES_SHOWN = 8


@dataclass
class Library:
    key: str
    name: str
    npm: str | None
    eol_product: str | None = None
    no_lookup: bool = False
    runtime: dict[str, set[str]] = field(default_factory=dict)  # version -> expressions
    static: dict[str, set[str]] = field(default_factory=dict)  # version -> methods
    filename: set[str] = field(default_factory=set)
    sources: dict[str, str] = field(default_factory=dict)  # version -> page (runtime)
    files: dict[str, str] = field(default_factory=dict)  # version -> JS file (static)
    present: bool = False
    unverified: bool = False

    def confident_versions(self) -> list[str]:
        out = list(self.runtime)
        for version in self.static:
            if all(versions.compare(version, v) != 0 for v in out):
                out.append(version)
        return out

    def method(self, version: str) -> str:
        parts = []
        if version in self.runtime:
            label = "runtime"
            if self.unverified:
                label += " (expression not verified)"
            parts.append(label)
        parts.extend(sorted(self.static.get(version, set())))
        return ", ".join(parts) or "-"


def _key(npm: str | None, name: str) -> str:
    return (npm or name).lower()


class JSGoblin(Goblin):
    name = "JSGoblin"
    flag = "javascript"
    prefix = "JS"
    order = 140
    uses_browser = True
    description = "JS library versions (runtime and static), latest, EOL, CVEs and SRI"

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        libs = self.collect(ctx)
        if ctx.browser is None:
            result.findings.append(
                self.not_assessed(ctx.target, "Runtime library detection", ctx.browser_reason)
            )
        intel = await self.intelligence(libs)
        rows: list[list[str]] = []
        for lib in sorted(libs.values(), key=lambda item: item.name.lower()):
            result.findings.extend(self._assess(ctx, lib, intel, rows))
        if rows:
            result.tables.append(
                Table(
                    title="JavaScript libraries",
                    columns=[
                        "Library",
                        "Detected",
                        "Method",
                        "Latest",
                        "EOL",
                        "CVEs",
                        "Status",
                        "Source",
                    ],
                    rows=rows,
                )
            )
        for note in intel.notes:
            result.findings.append(self.not_assessed(ctx.target, "Vulnerability lookups", note))
        result.findings.extend(self._sri(ctx))
        if not libs and not result.findings:
            result.not_assessed_reason = "no JavaScript libraries identified"
        return result

    def collect(self, ctx: TargetContext) -> dict[str, Library]:
        known = {lib.name: lib for lib in jsruntime.libraries()}
        libs: dict[str, Library] = {}

        def get(npm: str | None, name: str) -> Library:
            key = _key(npm, name)
            if key not in libs:
                runtime = next((k for k in known.values() if _key(k.npm, k.name) == key), None)
                libs[key] = Library(
                    key=key,
                    name=runtime.name if runtime else name,
                    npm=npm,
                    eol_product=runtime.eol if runtime else None,
                    no_lookup=runtime.no_lookup if runtime else False,
                )
            return libs[key]

        if ctx.browser is not None:
            for page in ctx.browser.pages:
                for name, found in (page.runtime or {}).items():
                    spec = known.get(name)
                    if spec is None:
                        continue
                    lib = get(spec.npm, spec.name)
                    lib.present = True
                    lib.unverified = spec.verified is False
                    if found.get("version"):
                        version = spec.normalise(found["version"])
                        lib.runtime.setdefault(version, set()).add(found.get("expression") or "")
                        lib.sources.setdefault(version, page.final_url or page.url)

        sources: list[tuple[str, str, bytes | None]] = []
        for page in ctx.store.js:
            sources.append((page.final_url or page.url, page.text, page.body))
        seen = {url for url, _, _ in sources}
        if ctx.browser is not None:
            for script in ctx.browser.scripts:
                if script.url not in seen:
                    sources.append((script.url, script.body, None))
                    seen.add(script.url)
        urls = [url for url, _, _ in sources] + [
            src for _, src in ctx.store.third_party_scripts if src not in seen
        ]
        for url in urls:
            for hit in _retire.scan_url(url):
                lib = get(hit.npm, hit.library)
                lib.present = True
                if hit.method == "filename":
                    lib.filename.add(hit.version)
                    lib.files.setdefault("", url)
                else:
                    lib.static.setdefault(hit.version, set()).add(hit.method)
                lib.files.setdefault(hit.version, url)
        for url, text, raw in sources:
            for hit in _retire.scan_content(url, text, raw):
                lib = get(hit.npm, hit.library)
                lib.present = True
                lib.static.setdefault(hit.version, set()).add(hit.method)
                lib.files.setdefault(hit.version, url)
        return libs

    async def intelligence(self, libs: dict[str, Library]) -> lookup.IntelReport:
        packages, eol, names = [], {}, []
        for lib in libs.values():
            if not lib.npm or lib.no_lookup:
                continue
            names.append(lib.npm)
            if lib.eol_product:
                eol[lib.npm] = lib.eol_product
            for version in lib.confident_versions():
                if versions.parse(version) is not None and (lib.npm, version) not in packages:
                    packages.append((lib.npm, version))
        if not names:
            return lookup.IntelReport()
        async with IntelClient() as client:
            return await lookup.libraries(client, packages, eol, sorted(set(names)))

    def _assess(
        self, ctx: TargetContext, lib: Library, intel: lookup.IntelReport, rows: list[list[str]]
    ) -> list[Finding]:
        out: list[Finding] = []
        info = intel.info_by_name.get(lib.npm) if lib.npm else None
        latest = info.latest if info else None
        latest_label = f"{latest} ({info.latest_date})" if info and latest else "-"
        detected = lib.confident_versions()
        if not detected:
            hint = f"filename suggests {', '.join(sorted(lib.filename))}" if lib.filename else ""
            source = next(iter([*lib.files.values(), *lib.sources.values()]), ctx.target)
            rows.append(
                [lib.name, "Unknown", hint or "present", latest_label, "-", "-", "Unknown", source]
            )
            out.append(
                self.finding(
                    title=f"{lib.name}: version unknown",
                    status=Status.OBSERVATION,
                    affected_url=source,
                    observed=f"{lib.name} is loaded but its version could not be established"
                    + (f" ({hint}; a filename alone is not trusted)" if hint else ""),
                    why_it_matters="CVE check not possible: version unknown.",
                    manual_steps=[
                        f"Check the {lib.name} version in the browser console or the file banner."
                    ],
                )
            )
            return out
        disagree = len(detected) > 1
        for version in detected:
            record = intel.libraries.get((lib.npm, version)) if lib.npm else None
            vulns = record.vulns if record else []
            eol = record.eol if record else None
            outdated = bool(latest) and (versions.compare(version, latest) or 0) < 0
            statuses = []
            if outdated:
                statuses.append("Outdated")
            if vulns:
                statuses.append("Known vulnerability")
            if eol and eol.startswith("EOL"):
                statuses.append("EOL")
            if not statuses:
                statuses.append("Current" if latest else "Not checked")
            source = lib.files.get(version) or lib.sources.get(version, ctx.target)
            cve_cell = (
                f"{len(vulns)}: "
                + ", ".join(v.label + (" (KEV)" if v.kev else "") for v in vulns[:3])
                if vulns
                else ("0" if record and lib.npm and not lib.no_lookup else "-")
            )
            shown = version + (" (versions disagree)" if disagree else "")
            rows.append(
                [
                    lib.name,
                    shown,
                    lib.method(version),
                    latest_label,
                    eol or "-",
                    cve_cell,
                    ", ".join(statuses),
                    source,
                ]
            )
            out.extend(self._findings(ctx, lib, version, vulns, eol, outdated, latest, source))
        return out

    def _reproduce(self, ctx: TargetContext, lib: Library, version: str, source: str) -> list[str]:
        steps = []
        if version in lib.runtime:
            expression = sorted(lib.runtime[version])[0]
            page = lib.sources.get(version, ctx.target)
            steps.append(f"Open {page} in a browser and run in the console: {expression}")
        file = lib.files.get(version)
        if version in lib.static and file:
            if ctx.client.scope.is_target(httpx.URL(file)):
                steps.append(ctx.curl(file, "-s") + " | head -c 400")
            else:
                steps.append(f"curl -s '{file}' | head -c 400")
        return steps or [f"Open {source} in a browser and check the library version"]

    def _findings(
        self,
        ctx: TargetContext,
        lib: Library,
        version: str,
        vulns,
        eol: str | None,
        outdated: bool,
        latest: str | None,
        source: str,
    ) -> list[Finding]:
        reproduce = self._reproduce(ctx, lib, version, source)
        method = lib.method(version)
        out: list[Finding] = []
        if vulns:
            lines = []
            for vuln in sorted(vulns, key=lambda v: -(v.cvss_score or 0))[:MAX_CVES_SHOWN]:
                parts = [vuln.label]
                if vuln.cvss_score is not None:
                    parts.append(f"CVSS {vuln.cvss_score}")
                elif vuln.severity:
                    parts.append(vuln.severity.title())
                parts.append(f"affected {vuln.affected}")
                if vuln.fixed:
                    parts.append(f"fixed in {vuln.fixed}")
                if vuln.epss is not None:
                    parts.append(f"EPSS {vuln.epss:.3f}")
                if vuln.kev:
                    parts.append("CISA KEV")
                parts.append("/".join(vuln.sources))
                lines.append("  ".join(parts) + (f"\n    {vuln.summary}" if vuln.summary else ""))
            if len(vulns) > MAX_CVES_SHOWN:
                lines.append(f"and {len(vulns) - MAX_CVES_SHOWN} more")
            fixes = [v.fixed for v in vulns if v.fixed]
            target = (
                max(fixes, key=lambda f: versions.parse(f) or versions.parse("0"))
                if fixes
                else None
            )
            out.append(
                self.finding(
                    title=f"{lib.name} {version} has known vulnerabilities",
                    status=Status.ISSUE,
                    affected_url=source,
                    observed=f"Detected by {method}\n" + "\n".join(lines),
                    expected=f"{target} or later" if target else None,
                    why_it_matters=(
                        "The detected version is inside the published affected range. Whether "
                        "each issue is exploitable depends on how the library is used."
                    ),
                    remediation=(
                        f"Upgrade {lib.name} to {target} or later"
                        + (f" (latest {latest})." if latest else ".")
                        if target
                        else f"Upgrade {lib.name} to a fixed release."
                    ),
                    reproduce=reproduce,
                    manual_steps=[
                        "Check whether the application uses the affected functions before "
                        "reporting each CVE as exploitable."
                    ],
                    references=[f"https://osv.dev/vulnerability/{v.id}" for v in vulns[:3]],
                )
            )
        elif outdated or (eol and eol.startswith("EOL")):
            out.append(
                self.finding(
                    title=f"{lib.name} {version} is "
                    + ("end of life" if eol and eol.startswith("EOL") else "outdated"),
                    status=Status.OBSERVATION,
                    affected_url=source,
                    observed=f"Detected {version} by {method}; latest {latest or 'unknown'}"
                    + (f"; {eol}" if eol else ""),
                    why_it_matters="No known vulnerability matched, but older releases miss "
                    "fixes and stop receiving security updates.",
                    remediation=f"Plan an upgrade to {latest}." if latest else None,
                    reproduce=reproduce,
                )
            )
        else:
            out.append(
                self.finding(
                    title=f"{lib.name} {version}",
                    status=Status.OK,
                    affected_url=source,
                    observed=f"Detected by {method}; no known vulnerability matched",
                    why_it_matters="Check passed.",
                )
            )
        return out

    def _sri(self, ctx: TargetContext) -> list[Finding]:
        missing: list[str] = []
        page_for: dict[str, str] = {}
        for page in ctx.store.html_pages():
            info = ctx.store.info(page)
            if info is None:
                continue
            for script in info.scripts:
                try:
                    url = httpx.URL(page.final_url or page.url).join(script.src)
                except (httpx.InvalidURL, ValueError):
                    continue
                if url.scheme not in ("http", "https") or ctx.client.scope.is_target(url):
                    continue
                if not script.integrity and str(url) not in missing:
                    missing.append(str(url))
                    page_for[str(url)] = page.final_url or page.url
        if not missing:
            return []
        first_page = page_for[missing[0]]
        return [
            self.finding(
                title="Third-party scripts without Subresource Integrity",
                status=Status.OBSERVATION,
                affected_url=first_page,
                observed="\n".join(missing[:15]),
                why_it_matters=(
                    "If the third-party host is compromised, altered script runs on this site. "
                    "SRI is only practical for fixed, versioned files."
                ),
                remediation="Add integrity and crossorigin attributes to versioned third-party "
                "scripts.",
                reproduce=[ctx.curl(first_page, "-s") + " | grep -oE '<script[^>]+src=[^>]+>'"],
            )
        ]

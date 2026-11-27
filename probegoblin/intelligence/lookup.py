"""Combines the sources for JS libraries: OSV first, then the optional ones, then EPSS and KEV."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from probegoblin.intelligence import endoflife, epss_kev, npm_registry, osv, snyk
from probegoblin.intelligence.cache import IntelClient, SourceError
from probegoblin.intelligence.npm_registry import PackageInfo
from probegoblin.intelligence.osv import Vuln


@dataclass
class LibraryIntel:
    package: str
    version: str
    info: PackageInfo | None = None
    eol: str | None = None
    vulns: list[Vuln] = field(default_factory=list)


@dataclass
class IntelReport:
    libraries: dict[tuple[str, str], LibraryIntel] = field(default_factory=dict)
    info_by_name: dict[str, PackageInfo | None] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def merge(primary: list[Vuln], extra: list[Vuln]) -> list[Vuln]:
    merged = list(primary)
    for vuln in extra:
        same = next((m for m in merged if m.keys & vuln.keys), None)
        if same:
            for source in vuln.sources:
                if source not in same.sources:
                    same.sources.append(source)
            same.fixed = same.fixed or vuln.fixed
            same.cvss_score = same.cvss_score or vuln.cvss_score
        else:
            merged.append(vuln)
    return merged


async def _safe(coro, notes: list[str], label: str):
    try:
        return await coro
    except SourceError as exc:
        note = f"{label}: {exc}"
        if note not in notes:
            notes.append(note)
        return None


async def libraries(
    client: IntelClient,
    packages: list[tuple[str, str]],
    eol_products: dict[str, str],
    latest_for: list[str],
) -> IntelReport:
    """packages: (npm name, version) with known versions. latest_for: npm names to look up."""
    report = IntelReport()
    notes = report.notes
    for package in packages:
        report.libraries[package] = LibraryIntel(*package)
    if packages:
        found = await _safe(osv.lookup(client, packages), notes, "OSV")
        if found is None:
            notes.append("CVE results are incomplete: OSV could not be reached")
        else:
            for package, vulns in found.items():
                report.libraries[package].vulns = vulns
    extras = []
    for package in packages:
        extras.append(_safe(snyk.github(client, *package), notes, "GitHub Advisories"))
        extras.append(_safe(snyk.snyk(client, *package), notes, "Snyk"))
    results = await asyncio.gather(*extras)
    for index, package in enumerate(packages):
        for extra in results[index * 2 : index * 2 + 2]:
            if extra:
                lib = report.libraries[package]
                lib.vulns = merge(lib.vulns, extra)

    cves = [c for lib in report.libraries.values() for v in lib.vulns for c in v.cves]
    if cves:
        scores = await _safe(epss_kev.epss(client, cves), notes, "EPSS")
        known = await _safe(epss_kev.kev(client), notes, "CISA KEV")
        for lib in report.libraries.values():
            for vuln in lib.vulns:
                for cve in vuln.cves:
                    if scores and cve in scores:
                        vuln.epss, vuln.epss_percentile = scores[cve]
                    if known and cve in known:
                        vuln.kev = True

    infos = await asyncio.gather(
        *(
            _safe(npm_registry.info(client, name, _version_of(packages, name)), notes, "npm")
            for name in latest_for
        )
    )
    info_by_name = dict(zip(latest_for, infos, strict=True))
    report.info_by_name = info_by_name
    eols = await asyncio.gather(
        *(
            _safe(endoflife.lookup(client, eol_products[name], version), notes, "endoflife.date")
            for name, version in packages
            if name in eol_products
        )
    )
    eol_iter = iter(eols)
    for name, version in packages:
        lib = report.libraries[(name, version)]
        lib.info = info_by_name.get(name)
        if name in eol_products:
            lib.eol = next(eol_iter)
    return report


def _version_of(packages: list[tuple[str, str]], name: str) -> str | None:
    return next((v for n, v in packages if n == name), None)

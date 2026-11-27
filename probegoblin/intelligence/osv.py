"""OSV.dev: the primary vulnerability source. Free, no key."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from probegoblin.intelligence import versions
from probegoblin.intelligence.cache import IntelClient
from probegoblin.intelligence.cvss import base_score

API = "https://api.osv.dev/v1"
BATCH = 500


@dataclass
class Vuln:
    id: str
    cves: list[str] = field(default_factory=list)
    summary: str = ""
    affected: str = ""
    fixed: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    sources: list[str] = field(default_factory=list)
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False

    @property
    def label(self) -> str:
        return self.cves[0] if self.cves else self.id

    @property
    def keys(self) -> set[str]:
        return {self.id, *self.cves}


def parse_vuln(data: dict, package: str, version: str) -> Vuln | None:
    """Keep the advisory only when the version is inside a published affected range."""
    for affected in data.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != "npm" or pkg.get("name") != package:
            continue
        hit = version in (affected.get("versions") or [])
        label, fixed = "", None
        for rng in affected.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            events = rng.get("events", [])
            if versions.in_osv_range(version, events):
                hit = True
                label, fixed = versions.osv_range_label(events)
                break
        if not hit:
            continue
        vector = next(
            (
                s["score"]
                for s in data.get("severity", [])
                if s.get("type", "").startswith("CVSS_V3")
            ),
            None,
        )
        if vector is None:
            vector = next((s["score"] for s in data.get("severity", [])), None)
        return Vuln(
            id=data["id"],
            cves=[a for a in data.get("aliases", []) if a.startswith("CVE-")],
            summary=data.get("summary") or (data.get("details") or "")[:160],
            affected=label or "listed versions",
            fixed=fixed,
            cvss_vector=vector,
            cvss_score=base_score(vector) if vector else None,
            severity=(data.get("database_specific") or {}).get("severity"),
            sources=["OSV"],
        )
    return None


async def lookup(
    client: IntelClient, packages: list[tuple[str, str]]
) -> dict[tuple[str, str], list[Vuln]]:
    results: dict[tuple[str, str], list[Vuln]] = {p: [] for p in packages}
    for start in range(0, len(packages), BATCH):
        chunk = packages[start : start + BATCH]
        body = {
            "queries": [
                {"package": {"name": name, "ecosystem": "npm"}, "version": version}
                for name, version in chunk
            ]
        }
        data = await client.json("osv", f"{API}/querybatch", method="POST", body=body)
        wanted: list[tuple[tuple[str, str], str]] = []
        for package, result in zip(chunk, data.get("results", []), strict=False):
            for vuln in result.get("vulns", []) or []:
                wanted.append((package, vuln["id"]))
        details = await asyncio.gather(
            *(client.json("osv", f"{API}/vulns/{vid}") for _, vid in wanted)
        )
        for (package, _vid), detail in zip(wanted, details, strict=True):
            if not detail:
                continue
            vuln = parse_vuln(detail, *package)
            if vuln:
                results[package].append(vuln)
    return results

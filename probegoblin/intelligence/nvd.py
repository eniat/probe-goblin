"""NVD: CPE-based lookups for server-side versions. Only used when NVD_API_KEY is set."""

from __future__ import annotations

import os
from dataclasses import dataclass

from probegoblin.intelligence import versions
from probegoblin.intelligence.cache import IntelClient

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESULTS = 200


@dataclass
class NvdCve:
    id: str
    score: float | None
    severity: str | None
    vector: str | None
    summary: str


def api_key() -> str | None:
    return os.environ.get("NVD_API_KEY") or None


def cpe_with_version(cpe: str, version: str) -> str | None:
    parts = cpe.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    parts[5] = version
    return ":".join(parts[:6])


def _metric(cve: dict) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        for entry in metrics.get(key, []):
            data = entry.get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity"), data.get("vectorString")
    return None, None, None


def _matches(cve: dict, cpe_prefix: str, version: str) -> bool:
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                vulnerable = match.get("vulnerable") and criteria.startswith(cpe_prefix)
                if vulnerable and versions.in_nvd_range(version, match):
                    return True
    return False


def parse(data: dict, cpe: str, version: str) -> list[NvdCve]:
    prefix = ":".join(cpe.split(":")[:5]) + ":"
    out = []
    for item in (data or {}).get("vulnerabilities", []):
        cve = item.get("cve", {})
        if not _matches(cve, prefix, version):
            continue
        score, severity, vector = _metric(cve)
        summary = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
        )
        out.append(NvdCve(cve.get("id", ""), score, severity, vector, summary[:200]))
    return out


async def lookup(client: IntelClient, cpe: str, version: str) -> list[NvdCve]:
    key = api_key()
    match = cpe_with_version(cpe, version)
    if key is None or match is None:
        return []
    data = await client.json(
        "nvd",
        API,
        params={"virtualMatchString": match, "resultsPerPage": str(MAX_RESULTS)},
        headers={"apiKey": key},
    )
    return parse(data, cpe, version)

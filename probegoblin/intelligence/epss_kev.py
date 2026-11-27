"""FIRST EPSS scores and the CISA Known Exploited Vulnerabilities catalogue."""

from __future__ import annotations

from probegoblin.intelligence.cache import IntelClient

EPSS = "https://api.first.org/data/v1/epss"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CHUNK = 100


async def epss(client: IntelClient, cves: list[str]) -> dict[str, tuple[float, float]]:
    scores: dict[str, tuple[float, float]] = {}
    unique = sorted(set(cves))
    for start in range(0, len(unique), CHUNK):
        chunk = unique[start : start + CHUNK]
        data = await client.json("epss", EPSS, params={"cve": ",".join(chunk)})
        for row in (data or {}).get("data", []):
            try:
                scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, ValueError):
                continue
    return scores


async def kev(client: IntelClient) -> set[str]:
    data = await client.json("kev", KEV)
    return {v["cveID"] for v in (data or {}).get("vulnerabilities", []) if "cveID" in v}

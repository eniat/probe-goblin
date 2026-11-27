"""npm registry: latest stable version and release dates."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from probegoblin.intelligence.cache import IntelClient

API = "https://registry.npmjs.org"


@dataclass
class PackageInfo:
    latest: str | None
    latest_date: str | None
    version_date: str | None


async def info(client: IntelClient, package: str, version: str | None) -> PackageInfo | None:
    data = await client.json("npm", f"{API}/{quote(package, safe='@')}", not_found=None)
    if not isinstance(data, dict):
        return None
    latest = (data.get("dist-tags") or {}).get("latest")
    times = data.get("time") or {}
    return PackageInfo(
        latest=latest,
        latest_date=(times.get(latest) or "")[:10] or None,
        version_date=(times.get(version) or "")[:10] or None if version else None,
    )

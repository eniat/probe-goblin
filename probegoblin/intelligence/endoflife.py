"""endoflife.date: support status of a release cycle."""

from __future__ import annotations

from probegoblin.intelligence import versions
from probegoblin.intelligence.cache import IntelClient

API = "https://endoflife.date/api/v1/products"


def status_for(data: dict, version: str) -> str | None:
    """'EOL since <date>', 'supported', or None when no cycle matches."""
    releases = (data.get("result") or {}).get("releases") or []
    parsed = versions.parse(version)
    if parsed is None:
        return None
    candidates = []
    for release in releases:
        name = str(release.get("name", ""))
        parts = name.split(".")
        wanted = [parsed.major, parsed.minor, parsed.patch][: len(parts)]
        if all(p.isdigit() and int(p) == w for p, w in zip(parts, wanted, strict=False)):
            candidates.append((len(parts), release))
    if not candidates:
        return None
    _, release = max(candidates, key=lambda c: c[0])
    if release.get("isEol"):
        since = release.get("eolFrom")
        return f"EOL since {since}" if since else "EOL"
    if release.get("isEoas"):
        return f"security fixes only since {release.get('eoasFrom')}"
    return "supported"


async def lookup(client: IntelClient, product: str, version: str) -> str | None:
    data = await client.json("endoflife", f"{API}/{product}", not_found=None)
    return status_for(data, version) if isinstance(data, dict) else None

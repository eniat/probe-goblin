"""HTTP client for vulnerability intelligence, with a 24 hour on-disk cache.

Only the hosts in ALLOWED_HOSTS can be contacted, and never the target."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx

from probegoblin import __version__


def cache_dir() -> Path:
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "probegoblin"


TTL = 24 * 3600
MAX_BYTES = 15 * 1024 * 1024
ALLOWED_HOSTS = {
    "api.osv.dev",
    "registry.npmjs.org",
    "endoflife.date",
    "api.first.org",
    "www.cisa.gov",
    "services.nvd.nist.gov",
    "api.github.com",
    "api.snyk.io",
}


cache_dir_default = cache_dir


class SourceError(Exception):
    """A source could not be reached or returned something unusable."""


class IntelClient:
    def __init__(self, cache_dir: Path | None = None, offline: bool = False) -> None:
        self.cache_dir = cache_dir or cache_dir_default()
        self.offline = offline
        self._client = httpx.AsyncClient(
            timeout=20,
            headers={"User-Agent": f"ProbeGoblin/{__version__}"},
            follow_redirects=False,
        )
        self._semaphore = asyncio.Semaphore(5)
        self.unreachable: dict[str, str] = {}

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> IntelClient:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    def _path(self, source: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()[:32]
        return self.cache_dir / source / f"{digest}.json"

    def _read(self, path: Path) -> Any | None:
        try:
            if time.time() - path.stat().st_mtime > TTL:
                return None
            return json.loads(path.read_text("utf-8"))
        except (OSError, ValueError):
            return None

    def _write(self, path: Path, data: Any) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), "utf-8")
            tmp.replace(path)
        except OSError:
            pass

    async def json(
        self,
        source: str,
        url: str,
        *,
        method: str = "GET",
        body: Any = None,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        not_found: Any = None,
    ) -> Any:
        """GET or POST JSON with caching. 404 returns `not_found`. Failures raise SourceError."""
        host = httpx.URL(url).host
        if host not in ALLOWED_HOSTS:
            raise SourceError(f"{host} is not an allowed intelligence source")
        key = json.dumps([method, url, body, params], sort_keys=True)
        path = self._path(source, key)
        cached = self._read(path)
        if cached is not None:
            return cached.get("data")
        if self.offline:
            raise SourceError("offline")
        if source in self.unreachable:
            raise SourceError(self.unreachable[source])
        async with self._semaphore:
            try:
                async with self._client.stream(
                    method, url, json=body, headers=headers, params=params
                ) as response:
                    if response.status_code == 404:
                        self._write(path, {"data": not_found})
                        return not_found
                    if response.status_code >= 400:
                        raise SourceError(f"{host} returned {response.status_code}")
                    chunks, size = [], 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_BYTES:
                            raise SourceError(f"{host} response too large")
                        chunks.append(chunk)
            except httpx.HTTPError as exc:
                reason = f"{host} unreachable ({type(exc).__name__})"
                self.unreachable[source] = reason
                raise SourceError(reason) from exc
        try:
            data = json.loads(b"".join(chunks))
        except ValueError as exc:
            raise SourceError(f"{host} returned invalid JSON") from exc
        self._write(path, {"data": data})
        return data

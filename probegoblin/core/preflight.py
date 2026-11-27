"""Target validation, DNS resolution and CDN labelling. Sends nothing to the target."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

from probegoblin.core import datafiles
from probegoblin.core.http_client import url_port

MAX_IPS = 4


@dataclass
class TargetPlan:
    raw: str
    url: str = ""
    host: str = ""
    scheme: str = ""
    port: int = 0
    ips: list[str] = field(default_factory=list)
    cdn: str | None = None
    pinned_ip: str | None = None
    note: str | None = None
    error: str | None = None


def validate_target(raw: str) -> tuple[str | None, str | None]:
    """Return (url, error). The hostname is never changed."""
    value = raw.strip()
    if not value:
        return None, "empty target"
    if "://" not in value:
        return None, f"{value}: include the scheme, for example https://{value}"
    try:
        url = httpx.URL(value)
    except (httpx.InvalidURL, ValueError) as exc:
        return None, f"{value}: invalid URL ({exc})"
    if url.scheme not in ("http", "https"):
        return None, f"{value}: only http and https targets are supported"
    if not url.host:
        return None, f"{value}: no hostname"
    if url.userinfo:
        return None, f"{value}: remove credentials from the URL, use --cookie or --header instead"
    parts = urlsplit(str(url.copy_with(fragment=None)))
    return urlunsplit(parts._replace(path=parts.path or "/")), None


def validate_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip().strip("[]")))


def read_targets_file(path: Path) -> list[str]:
    targets = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    return targets


@lru_cache(maxsize=1)
def _cdn_data() -> dict[str, dict[str, list]]:
    text = datafiles.read_text("cdn_ranges.toml")
    data = tomllib.loads(text).get("cdn", {})
    parsed: dict[str, dict[str, list]] = {}
    for name, entry in data.items():
        parsed[name] = {
            "ranges": [ipaddress.ip_network(r) for r in entry.get("ranges", [])],
            "rdns": [s.lower() for s in entry.get("rdns", [])],
        }
    return parsed


def cdn_for(ip: str, rdns: str | None) -> str | None:
    address = ipaddress.ip_address(ip)
    for name, entry in _cdn_data().items():
        if any(address in net for net in entry["ranges"] if net.version == address.version):
            return name
    if rdns:
        rdns = rdns.lower().rstrip(".")
        for name, entry in _cdn_data().items():
            if any(rdns.endswith(suffix) for suffix in entry["rdns"]):
                return name
    return None


async def _reverse(ip: str) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        host, _, _ = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 3)
        return host
    except (OSError, TimeoutError):
        return None


async def resolve(host: str, port: int) -> list[str]:
    try:
        return [str(ipaddress.ip_address(host.strip("[]")))]
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


async def plan_target(raw: str, pinned_ip: str | None = None) -> TargetPlan:
    plan = TargetPlan(raw=raw, pinned_ip=pinned_ip)
    url, error = validate_target(raw)
    if error:
        plan.error = error
        return plan
    parsed = httpx.URL(url)
    plan.url, plan.host, plan.scheme, plan.port = url, parsed.host, parsed.scheme, url_port(parsed)
    try:
        ips = await asyncio.wait_for(resolve(plan.host, plan.port), 10)
    except (OSError, TimeoutError):
        ips = []
    if pinned_ip:
        if not ips:
            plan.note = f"{plan.host} does not resolve, connecting to pinned {pinned_ip}"
        elif pinned_ip not in ips:
            plan.note = f"DNS gives {', '.join(ips[:MAX_IPS])}, connecting to pinned {pinned_ip}"
        plan.ips = [pinned_ip]
    elif not ips:
        plan.error = f"{plan.host} does not resolve, target skipped"
        return plan
    else:
        plan.ips = ips[:MAX_IPS]
    names = await asyncio.gather(*(_reverse(ip) for ip in plan.ips))
    for ip, name in zip(plan.ips, names, strict=True):
        label = cdn_for(ip, name)
        if label:
            plan.cdn = label
            break
    return plan

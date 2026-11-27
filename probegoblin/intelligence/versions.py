"""Version parsing and range checks with semver. Version strings are never compared directly."""

from __future__ import annotations

import re

import semver

_LOOSE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.\d+)*(?:[-.]?([0-9A-Za-z.-]+))?(?:\+.*)?$"
)


def parse(value: str | None) -> semver.Version | None:
    """Coerce '1.12' to 1.12.0 and '3.0.0-rc.1' as a pre-release. None if it is not a version."""
    if not value:
        return None
    value = str(value).strip()
    try:
        return semver.Version.parse(value.lstrip("v"))
    except ValueError:
        pass
    match = _LOOSE.match(value)
    if not match:
        return None
    major, minor, patch, pre = match.groups()
    try:
        return semver.Version(int(major), int(minor or 0), int(patch or 0), prerelease=pre or None)
    except ValueError:
        return semver.Version(int(major), int(minor or 0), int(patch or 0))


def compare(a: str, b: str) -> int | None:
    va, vb = parse(a), parse(b)
    if va is None or vb is None:
        return None
    return va.compare(vb)


def in_osv_range(version: str, events: list[dict]) -> bool:
    """OSV SEMVER/ECOSYSTEM events: introduced, fixed, last_affected, limit."""
    v = parse(version)
    if v is None:
        return False
    affected = False
    for event in events:
        if "introduced" in event:
            start = event["introduced"]
            if start == "0" or (parse(start) is not None and v >= parse(start)):
                affected = True
        elif "fixed" in event:
            fixed = parse(event["fixed"])
            if fixed is not None and v >= fixed:
                affected = False
        elif "last_affected" in event:
            last = parse(event["last_affected"])
            if last is not None and v > last:
                affected = False
        elif "limit" in event:
            limit = parse(event["limit"])
            if limit is not None and v >= limit:
                affected = False
    return affected


def osv_range_label(events: list[dict]) -> tuple[str, str | None]:
    """Human range and the fixed version."""
    parts, fixed = [], None
    for event in events:
        if "introduced" in event:
            parts.append(f">={event['introduced']}" if event["introduced"] != "0" else ">=0")
        elif "fixed" in event:
            parts.append(f"<{event['fixed']}")
            fixed = fixed or event["fixed"]
        elif "last_affected" in event:
            parts.append(f"<={event['last_affected']}")
    return " ".join(parts) or "all versions", fixed


def in_nvd_range(version: str, match: dict) -> bool:
    v = parse(version)
    if v is None:
        return False
    checks = [
        ("versionStartIncluding", lambda b: v >= b),
        ("versionStartExcluding", lambda b: v > b),
        ("versionEndIncluding", lambda b: v <= b),
        ("versionEndExcluding", lambda b: v < b),
    ]
    bounded = False
    for key, test in checks:
        if key in match:
            bound = parse(match[key])
            if bound is None or not test(bound):
                return False
            bounded = True
    if bounded:
        return True
    parts = match.get("criteria", "").split(":")
    exact = parts[5] if len(parts) > 5 else "*"
    return exact not in ("*", "-") and parse(exact) == v

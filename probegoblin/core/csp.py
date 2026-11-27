"""Content-Security-Policy parsing, shared by HeaderGoblin and ClickjackGoblin."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

from probegoblin.core import datafiles
from probegoblin.core.htmlparse import HtmlInfo
from probegoblin.core.models import Page

META_IGNORED = ("frame-ancestors", "report-uri", "sandbox")
SCHEME_SOURCES = ("http:", "https:", "data:", "blob:", "filesystem:", "ws:", "wss:")


@dataclass
class Policy:
    raw: str
    source: str  # "header" or "meta"
    report_only: bool = False
    directives: dict[str, list[str]] = field(default_factory=dict)
    duplicates: list[str] = field(default_factory=list)

    @property
    def enforced(self) -> bool:
        return not self.report_only

    def get(self, name: str) -> list[str] | None:
        return self.directives.get(name)

    def effective(self, name: str) -> tuple[str | None, list[str] | None]:
        """The directive that applies, falling back to default-src."""
        if name in self.directives:
            return name, self.directives[name]
        if "default-src" in self.directives:
            return "default-src", self.directives["default-src"]
        return None, None


def parse_policy(raw: str, source: str, report_only: bool = False) -> Policy:
    policy = Policy(raw=raw.strip(), source=source, report_only=report_only)
    for part in raw.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name in policy.directives:
            policy.duplicates.append(name)
            continue
        policy.directives[name] = [_normal(t) for t in tokens[1:]]
    return policy


def _normal(token: str) -> str:
    lowered = token.lower()
    if lowered.startswith("'") or lowered.endswith(":") or lowered == "*":
        return lowered
    return token


def page_policies(page: Page, info: HtmlInfo | None) -> list[Policy]:
    policies: list[Policy] = []
    for header, report_only in (
        ("content-security-policy", False),
        ("content-security-policy-report-only", True),
    ):
        for value in page.header_all(header):
            for serialised in value.split(","):
                if serialised.strip():
                    policies.append(parse_policy(serialised, "header", report_only))
    if info is not None:
        for value in info.http_equiv("content-security-policy"):
            if value.strip():
                policies.append(parse_policy(value, "meta"))
    return policies


def has_nonce_or_hash(sources: list[str]) -> bool:
    return any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources)


@lru_cache(maxsize=1)
def bypass_entries() -> list[tuple[str, str, str, bool]]:
    """(host, path, kind, needs_eval) from data/csp_bypass.txt."""
    text = datafiles.read_text("csp_bypass.txt")
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        url = parts[0].removeprefix("//")
        host, _, path = url.partition("/")
        kind = parts[1] if len(parts) > 1 else "jsonp"
        entries.append((host.lower(), "/" + path, kind, "needs-eval" in parts))
    return entries


def _source_host_path(source: str) -> tuple[str, str] | None:
    if source.startswith("'") or source in ("*",) or source.endswith(":"):
        return None
    value = source.split("://", 1)[1] if "://" in source else source
    host, _, path = value.partition("/")
    host = host.split(":", 1)[0].lower()
    return (host, "/" + path if path else "") if host else None


def _host_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return pattern == host


def bypass_hosts(sources: list[str], allows_eval: bool) -> list[tuple[str, str]]:
    """Allowlisted sources that match a known bypass host. Returns (source, kind)."""
    hits: list[tuple[str, str]] = []
    for source in sources:
        parsed = _source_host_path(source)
        if parsed is None:
            continue
        pattern, path = parsed
        for host, bypass_path, kind, needs_eval in bypass_entries():
            if needs_eval and not allows_eval:
                continue
            if not _host_matches(pattern, host):
                continue
            if path and not (
                bypass_path.startswith(path) if path.endswith("/") else bypass_path == path
            ):
                continue
            if (source, kind) not in hits:
                hits.append((source, kind))
            break
    return hits


def broad_wildcards(sources: list[str]) -> list[str]:
    out = []
    for source in sources:
        parsed = _source_host_path(source)
        if parsed and parsed[0].startswith("*."):
            out.append(source)
    return out

"""Result and page models shared by the engine, modules and renderer."""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, Field


class Status(str, Enum):
    ISSUE = "issue"
    OBSERVATION = "observation"
    MANUAL_CHECK = "manual_check"
    OK = "ok"
    NOT_ASSESSED = "not_assessed"


class Finding(BaseModel):
    finding_id: str = ""
    module: str
    title: str
    status: Status
    affected_url: str
    observed: str | None = None
    expected: str | None = None
    why_it_matters: str
    remediation: str | None = None
    reproduce: list[str] = Field(default_factory=list)
    manual_steps: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class Table(BaseModel):
    """A table a module wants rendered under its section (cookies, libraries, TLS)."""

    title: str
    columns: list[str]
    rows: list[list[str]]


class ModuleResult(BaseModel):
    module: str
    findings: list[Finding] = Field(default_factory=list)
    tables: list[Table] = Field(default_factory=list)
    not_assessed_reason: str | None = None
    duration: float = 0.0

    def count(self, status: Status) -> int:
        return sum(1 for f in self.findings if f.status == status)


class Hop(BaseModel):
    """One response in a redirect chain."""

    url: str
    status: int
    headers: list[tuple[str, str]]

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]


class Page(BaseModel):
    """One fetched URL in the page store."""

    url: str
    source: str
    method: str = "GET"
    status: int | None = None
    final_url: str | None = None
    headers: list[tuple[str, str]] = Field(default_factory=list)
    body: bytes = b""
    truncated: bool = False
    chain: list[Hop] = Field(default_factory=list)
    offsite_redirect: str | None = None
    error: str | None = None
    tags: set[str] = Field(default_factory=set)
    soft_404: bool = False
    elapsed: float = 0.0

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip().lower()

    @property
    def is_html(self) -> bool:
        if self.content_type in ("text/html", "application/xhtml+xml"):
            return True
        if not self.content_type:
            return self.body.lstrip()[:15].lower().startswith((b"<!doctype html", b"<html"))
        return False

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300 and not self.soft_404

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def body_hash(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


class TargetResult(BaseModel):
    target: str
    host: str
    ips: list[str] = Field(default_factory=list)
    cdn: str | None = None
    pinned_ip: str | None = None
    skipped_reason: str | None = None
    tech_summary: list[str] = Field(default_factory=list)
    favicon_hash: int | None = None
    waf_summary: str | None = None
    tls_summary: str | None = None
    requests_sent: int = 0
    pages_browsed: int = 0
    blocked: int = 0
    duration: float = 0.0
    modules: list[ModuleResult] = Field(default_factory=list)
    skipped_urls: list[str] = Field(default_factory=list)
    interrupted: bool = False

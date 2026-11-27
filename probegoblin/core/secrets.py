"""Secret patterns and redaction. Secrets are never shown beyond their first 4 characters."""

from __future__ import annotations

import re
from dataclasses import dataclass

from probegoblin.core.models import Status

PLACEHOLDER = re.compile(
    r"^(x+|\*+|0+|your[_-]?|<|\$\{|\{\{|%|process\.env|example|sample|test|changeme|dummy|"
    r"placeholder|null|undefined|true|false|none)",
    re.I,
)


@dataclass(frozen=True)
class SecretPattern:
    kind: str
    regex: re.Pattern
    status: Status
    note: str = ""
    group: int = 0


def _p(kind: str, pattern: str, status: Status, note: str = "", group: int = 0) -> SecretPattern:
    return SecretPattern(kind, re.compile(pattern), status, note, group)


PATTERNS: list[SecretPattern] = [
    _p("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", Status.ISSUE),
    _p(
        "AWS secret access key",
        r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"]([0-9a-zA-Z/+]{40})['\"]",
        Status.ISSUE,
        group=1,
    ),
    _p(
        "Google API key",
        r"\bAIza[0-9A-Za-z_\-]{35}\b",
        Status.MANUAL_CHECK,
        "Google browser keys (Maps and similar) are public by design; check the key's API "
        "and referrer restrictions.",
    ),
    _p("Stripe secret key", r"\bsk_live_[0-9a-zA-Z]{24,}\b", Status.ISSUE),
    _p("Stripe restricted key", r"\brk_live_[0-9a-zA-Z]{24,}\b", Status.ISSUE),
    _p(
        "Stripe publishable key",
        r"\bpk_live_[0-9a-zA-Z]{24,}\b",
        Status.MANUAL_CHECK,
        "Publishable keys are meant to be in client code.",
    ),
    _p(
        "Stripe test secret key",
        r"\bsk_test_[0-9a-zA-Z]{24,}\b",
        Status.MANUAL_CHECK,
        "Test mode key: no live payments, but it still grants API access to test data.",
    ),
    _p("Slack token", r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b", Status.ISSUE),
    _p(
        "Slack webhook",
        r"https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+",
        Status.ISSUE,
    ),
    _p(
        "GitHub token",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b",
        Status.ISSUE,
    ),
    _p(
        "Private key",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
        Status.ISSUE,
    ),
    _p(
        "JWT",
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        Status.MANUAL_CHECK,
        "Could be a sample or an anonymous token; decode it and check what it grants.",
    ),
    _p(
        "Generic secret assignment",
        r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|"
        r"auth[_-]?token|secret|password|passwd)\b['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]",
        Status.MANUAL_CHECK,
        "Matched by name only; confirm it is a real credential.",
        group=1,
    ),
]


def mask(value: str) -> str:
    """First 4 characters, then a marker of how long the value was."""
    return f"{value[:4]}...({len(value)} chars)" if len(value) > 4 else "****"


@dataclass
class SecretHit:
    kind: str
    value: str
    status: Status
    note: str
    line: int


def find_secrets(text: str) -> list[SecretHit]:
    hits: list[SecretHit] = []
    seen: set[str] = set()
    for pattern in PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(pattern.group)
            if pattern.group and PLACEHOLDER.match(value):
                continue
            if value in seen:
                continue
            seen.add(value)
            line = text.count("\n", 0, match.start()) + 1
            hits.append(SecretHit(pattern.kind, value, pattern.status, pattern.note, line))
    return hits


def redact_text(text: str) -> str:
    """Replace every secret found in text with its masked form."""
    for hit in find_secrets(text):
        text = text.replace(hit.value, mask(hit.value))
    return text


def grep_for(kind: str) -> str:
    """A grep -oP expression that finds this kind of secret without printing it in the command."""
    for pattern in PATTERNS:
        if pattern.kind == kind:
            return pattern.regex.pattern.replace("'", "'\\''")
    return ""

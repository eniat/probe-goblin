"""Helpers modules share for building findings."""

from __future__ import annotations

from probegoblin.core.models import Finding

MAX_LISTED = 5


def merge_across_pages(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that are identical apart from the page into one, listing the pages."""
    groups: dict[tuple, list[Finding]] = {}
    for finding in findings:
        key = (finding.title, finding.status, finding.observed, finding.expected)
        groups.setdefault(key, []).append(finding)
    merged: list[Finding] = []
    for group in groups.values():
        first = group[0]
        others = []
        for finding in group[1:]:
            if finding.affected_url != first.affected_url and finding.affected_url not in others:
                others.append(finding.affected_url)
        if others:
            first = first.model_copy(deep=True)
            shown = ", ".join(others[:MAX_LISTED])
            if len(others) > MAX_LISTED:
                shown += f" and {len(others) - MAX_LISTED} more"
            first.observed = f"{first.observed or ''}\nAlso on: {shown}".strip()
        merged.append(first)
    return merged

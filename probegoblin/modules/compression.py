"""CompressionGoblin: HTTP compression and BREACH conditions, from responses already fetched."""

from __future__ import annotations

import re

from probegoblin.core.context import TargetContext
from probegoblin.core.models import ModuleResult, Page, Status
from probegoblin.core.registry import Goblin

TOKEN_NAME = re.compile(
    r"csrf|xsrf|_token|authenticity_token|requestverificationtoken|anti.?forgery", re.I
)
TOKEN_VALUE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")


def csrf_token(ctx: TargetContext, page: Page) -> str | None:
    """Name of a secret-looking token in the response body, if any."""
    info = ctx.store.info(page)
    if info is None:
        return None
    for meta in info.metas:
        name = meta.get("name", "")
        if TOKEN_NAME.search(name) and TOKEN_VALUE.fullmatch(meta.get("content", "")):
            return f"meta {name}"
    text = page.text
    for form in info.forms:
        for _kind, name in form.inputs:
            if name and TOKEN_NAME.search(name):
                value = re.search(
                    r"name=[\"']?" + re.escape(name) + r"[\"']?[^>]*value=[\"']([^\"']+)", text
                ) or re.search(r"value=[\"']([^\"']+)[\"'][^>]*name=[\"']?" + re.escape(name), text)
                if value and TOKEN_VALUE.fullmatch(value.group(1)):
                    return f"form field {name}"
    return None


class CompressionGoblin(Goblin):
    name = "CompressionGoblin"
    flag = "compression"
    prefix = "CMP"
    order = 60
    description = "Content-Encoding and BREACH preconditions (no extra requests)"

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        pages = [p for p in ctx.store.sensitive_pages() if p.status and p.is_html]
        if not pages:
            result.not_assessed_reason = "no HTML pages returned"
            return result
        for page in pages:
            url = page.final_url or page.url
            encoding = page.header("content-encoding")
            reproduce = [
                ctx.curl(url, "-s", "-o /dev/null", "-D -", "-H 'Accept-Encoding: gzip, br'")
                + " | grep -i '^content-encoding:'"
            ]
            if not encoding or encoding.lower() == "identity":
                result.findings.append(
                    self.finding(
                        title="Response not compressed",
                        status=Status.OK,
                        affected_url=url,
                        observed="No Content-Encoding",
                        why_it_matters="Check passed.",
                    )
                )
                continue
            result.findings.append(
                self.finding(
                    title=f"HTTP compression enabled ({encoding})",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=f"Content-Encoding: {encoding}",
                    why_it_matters="Not a problem by itself. It is one precondition for BREACH.",
                    reproduce=reproduce,
                )
            )
            token = csrf_token(ctx, page)
            if token:
                result.findings.append(
                    self.finding(
                        title="BREACH conditions may be present",
                        status=Status.MANUAL_CHECK,
                        affected_url=url,
                        observed=f"Compressed ({encoding}) response contains a secret token "
                        f"({token})",
                        why_it_matters=(
                            "If attacker-controlled input is reflected in the same compressed "
                            "response, the token may be recoverable from response sizes."
                        ),
                        remediation=(
                            "Mask tokens per response (XOR with a random value), or disable "
                            "compression for responses containing secrets."
                        ),
                        reproduce=reproduce,
                        manual_steps=[
                            "Check whether any request input is reflected in this response.",
                            "Check whether the token changes on every response.",
                            "Only report BREACH if reflection and a static token are both present.",
                        ],
                        references=["https://www.breachattack.com/"],
                    )
                )
        return result

"""WAFGoblin: wafw00f, corroborated with CDN and WAF headers already seen. Runs last."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from probegoblin.core.context import TargetContext
from probegoblin.core.external import INSTALL_HINTS, find_tool, run_tool
from probegoblin.core.models import ModuleResult, Status
from probegoblin.core.registry import STAGE_EXTERNAL, Goblin

# Vendor: list of (kind, name, value regex or None).
SIGNS: dict[str, list[tuple[str, str, str | None]]] = {
    "Cloudflare": [
        ("header", "cf-ray", None),
        ("header", "server", r"^cloudflare"),
        ("cookie", "__cf_bm", None),
        ("cookie", "cf_clearance", None),
    ],
    "Amazon CloudFront": [
        ("header", "x-amz-cf-id", None),
        ("header", "x-amz-cf-pop", None),
        ("header", "via", r"cloudfront"),
    ],
    "AWS WAF or ALB": [("cookie", "awsalb", None), ("cookie", "awsalbcors", None)],
    "Akamai": [
        ("header", "akamai-grn", None),
        ("header", "x-akamai-transformed", None),
        ("header", "x-akamai-request-id", None),
        ("cookie", "ak_bmsc", None),
        ("cookie", "_abck", None),
    ],
    "Imperva Incapsula": [
        ("header", "x-iinfo", None),
        ("header", "x-cdn", r"incapsula|imperva"),
        ("cookie", "incap_ses_", None),
        ("cookie", "visid_incap_", None),
    ],
    "Sucuri": [("header", "x-sucuri-id", None), ("header", "x-sucuri-cache", None)],
    "Fastly": [("header", "x-fastly-request-id", None), ("header", "x-served-by", r"cache-")],
    "Azure Front Door": [("header", "x-azure-ref", None)],
    "F5 BIG-IP": [("cookie", "bigipserver", None), ("cookie", "ts01", None)],
    "Barracuda": [("cookie", "barra_counter_session", None)],
    "Fortinet FortiWeb": [("cookie", "fortiwafsid", None)],
}


def parse_wafw00f(text: str) -> list[dict]:
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError("unexpected wafw00f JSON layout")
    return [entry for entry in data if isinstance(entry, dict)]


def header_evidence(ctx: TargetContext) -> dict[str, list[str]]:
    evidence: dict[str, list[str]] = {}
    for page in ctx.store.all_pages():
        for hop in page.chain:
            for key, value in hop.headers:
                lower = key.lower()
                cookie = value.split("=", 1)[0].strip().lower() if lower == "set-cookie" else None
                for vendor, signs in SIGNS.items():
                    for kind, name, pattern in signs:
                        if kind == "header" and lower == name:
                            if pattern is None or re.search(pattern, value, re.I):
                                label = f"{key} header"
                            else:
                                continue
                        elif kind == "cookie" and cookie and cookie.startswith(name):
                            label = f"{cookie} cookie"
                        else:
                            continue
                        found = evidence.setdefault(vendor, [])
                        if label not in found:
                            found.append(label)
    return evidence


class WAFGoblin(Goblin):
    name = "WAFGoblin"
    flag = "waf"
    prefix = "WAF"
    order = 900
    stage = STAGE_EXTERNAL
    description = "wafw00f vendor detection, corroborated with CDN and WAF headers"

    def unavailable_reason(self) -> str | None:
        if find_tool("wafw00f") is None:
            return f"wafw00f not found ({INSTALL_HINTS['wafw00f']})"
        return None

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        evidence = header_evidence(ctx)
        detected, tool_note = await self._wafw00f(ctx)
        url = ctx.target
        reproduce = [ctx.curl(url, "-sI")]
        if detected:
            vendor = detected.get("firewall") or "unknown"
            maker = detected.get("manufacturer")
            sources = ["wafw00f"] + [
                e for v, es in evidence.items() for e in es if _match(v, vendor)
            ]
            ctx.summary["waf"] = f"{vendor} ({', '.join(sources)})"
            result.findings.append(
                self.finding(
                    title=f"WAF identified: {vendor}",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=f"wafw00f: {vendor}"
                    + (f" by {maker}" if maker and maker != vendor else ""),
                    why_it_matters="Payload-based testing may be blocked or altered.",
                    reproduce=reproduce,
                )
            )
        elif tool_note is None:
            ctx.summary["waf"] = "No WAF identified by wafw00f"
            result.findings.append(
                self.finding(
                    title="No WAF identified by wafw00f",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed="wafw00f did not match a known WAF",
                    why_it_matters="This does not mean there is no WAF; many are not "
                    "fingerprinted by wafw00f.",
                )
            )
        else:
            result.findings.append(self.not_assessed(url, "wafw00f detection", tool_note))
        for vendor, labels in evidence.items():
            if detected and _match(vendor, detected.get("firewall") or ""):
                continue
            if "waf" not in ctx.summary:
                ctx.summary["waf"] = f"{vendor} ({', '.join(labels)})"
            result.findings.append(
                self.finding(
                    title=f"{vendor} indicators in responses",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=", ".join(labels),
                    why_it_matters="Headers or cookies point to this CDN or WAF.",
                    reproduce=reproduce,
                )
            )
        return result

    async def _wafw00f(self, ctx: TargetContext) -> tuple[dict | None, str | None]:
        """(detected entry, reason it could not be assessed)."""
        if ctx.settings.pinned_ip:
            return None, "wafw00f cannot be pinned to --ip, so it would test a different server"
        path = find_tool("wafw00f")
        if path is None:
            return None, f"wafw00f not found ({INSTALL_HINTS['wafw00f']})"
        limit = ctx.settings.tool_limits.wafw00f
        with tempfile.TemporaryDirectory(prefix="probegoblin-") as tmp:
            out = Path(tmp) / "wafw00f.json"
            try:
                run = await run_tool([path, ctx.target, "-o", str(out)], limit)
            except OSError as exc:
                return None, f"wafw00f failed to start: {exc}"
            if run.timed_out:
                return None, "timed out"
            try:
                entries = parse_wafw00f(out.read_text("utf-8"))
            except (OSError, ValueError):
                return None, "could not parse wafw00f output"
        if not entries:
            down = re.search(r"ERROR:wafw00f:(.+)", run.stderr + run.stdout)
            reason = down.group(1).strip()[:160] if down else "wafw00f returned no result"
            return None, reason
        for entry in entries:
            if entry.get("detected"):
                return entry, None
        return None, None


def _match(vendor: str, wafw00f_name: str) -> bool:
    a, b = vendor.lower(), wafw00f_name.lower()
    return a.split()[0] in b or b.split()[0] in a if a and b else False

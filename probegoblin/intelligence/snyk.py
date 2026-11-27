"""Optional extra sources, official APIs only: Snyk (SNYK_TOKEN and SNYK_ORG_ID) and GitHub
Advisories (GITHUB_TOKEN). The Snyk website is never scraped.

Both parsers follow the providers' published API documentation. Neither could be tested
against a live account while ProbeGoblin was written, so their results are labelled with
the source and OSV remains the primary source."""

from __future__ import annotations

import os
from urllib.parse import quote

from probegoblin.intelligence.cache import IntelClient
from probegoblin.intelligence.osv import Vuln

SNYK_API = "https://api.snyk.io/rest"
SNYK_VERSION = "2024-10-15"
GITHUB_API = "https://api.github.com/advisories"


def snyk_configured() -> bool:
    return bool(os.environ.get("SNYK_TOKEN") and os.environ.get("SNYK_ORG_ID"))


def github_configured() -> bool:
    return bool(os.environ.get("GITHUB_TOKEN"))


def parse_snyk(data: dict) -> list[Vuln]:
    out = []
    for issue in (data or {}).get("data", []):
        attrs = issue.get("attributes", {})
        cves = [
            p["id"] for p in attrs.get("problems", []) if str(p.get("id", "")).startswith("CVE-")
        ]
        out.append(
            Vuln(
                id=str(issue.get("id", attrs.get("key", ""))),
                cves=cves,
                summary=attrs.get("title", ""),
                affected="per Snyk",
                severity=(attrs.get("effective_severity_level") or "").upper() or None,
                sources=["Snyk"],
            )
        )
    return out


async def snyk(client: IntelClient, package: str, version: str) -> list[Vuln]:
    if not snyk_configured():
        return []
    purl = quote(f"pkg:npm/{package}@{version}", safe="")
    org = os.environ["SNYK_ORG_ID"]
    data = await client.json(
        "snyk",
        f"{SNYK_API}/orgs/{org}/packages/{purl}/issues",
        params={"version": SNYK_VERSION},
        headers={"Authorization": f"token {os.environ['SNYK_TOKEN']}"},
    )
    return parse_snyk(data)


def parse_github(data: list, package: str) -> list[Vuln]:
    out = []
    for advisory in data or []:
        affected, fixed = "", None
        for vuln in advisory.get("vulnerabilities", []):
            pkg = vuln.get("package") or {}
            if pkg.get("ecosystem") == "npm" and pkg.get("name") == package:
                affected = vuln.get("vulnerable_version_range") or ""
                fixed = vuln.get("first_patched_version")
        cvss = advisory.get("cvss") or {}
        out.append(
            Vuln(
                id=advisory.get("ghsa_id", ""),
                cves=[advisory["cve_id"]] if advisory.get("cve_id") else [],
                summary=advisory.get("summary", ""),
                affected=affected,
                fixed=fixed,
                cvss_score=cvss.get("score"),
                cvss_vector=cvss.get("vector_string"),
                severity=(advisory.get("severity") or "").upper() or None,
                sources=["GitHub"],
            )
        )
    return out


async def github(client: IntelClient, package: str, version: str) -> list[Vuln]:
    if not github_configured():
        return []
    data = await client.json(
        "github",
        GITHUB_API,
        params={"ecosystem": "npm", "affects": f"{package}@{version}", "per_page": "100"},
        headers={
            "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
            "Accept": "application/vnd.github+json",
        },
    )
    return parse_github(data, package)

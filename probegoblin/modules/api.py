"""APIGoblin: API documentation, version disclosure, verbose errors, GraphQL introspection."""

from __future__ import annotations

import json
from urllib.parse import quote

import httpx

from probegoblin.core.context import TargetContext
from probegoblin.core.models import Finding, ModuleResult, Page, Status
from probegoblin.core.registry import Goblin

INTROSPECTION = "{__schema{queryType{name}}}"
ERROR_KEYS = {"stack", "stacktrace", "stack_trace", "trace", "exception", "traceback", "exc_info"}
VERSION_KEYS = {"version", "apiversion", "api_version", "build", "release"}


def as_json(page: Page):
    try:
        return json.loads(page.body)
    except (ValueError, UnicodeDecodeError):
        return None


def openapi_summary(data) -> str | None:
    if not isinstance(data, dict) or not ("swagger" in data or "openapi" in data):
        return None
    info = data.get("info") or {}
    paths = data.get("paths") or {}
    operations = sum(len(v) for v in paths.values() if isinstance(v, dict))
    spec = f"OpenAPI {data['openapi']}" if "openapi" in data else f"Swagger {data['swagger']}"
    return (
        f"{spec}, title {info.get('title', '-')!r}, version {info.get('version', '-')}, "
        f"{len(paths)} paths, {operations} operations"
    )


def error_keys(data, depth: int = 0) -> list[str]:
    if depth > 3:
        return []
    found = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in ERROR_KEYS and value:
                found.append(key)
            found.extend(error_keys(value, depth + 1))
    elif isinstance(data, list):
        for item in data[:5]:
            found.extend(error_keys(item, depth + 1))
    return found


class APIGoblin(Goblin):
    name = "APIGoblin"
    flag = "api"
    prefix = "API"
    order = 120
    description = "Swagger and OpenAPI docs, API version disclosure, verbose errors, GraphQL"

    def estimate_requests(self, settings) -> int:
        return 1

    def api_pages(self, ctx: TargetContext) -> list[Page]:
        root = ctx.target.rstrip("/")
        wanted = {root + path for path in ctx.settings.api_paths}
        return [
            p
            for p in ctx.store.all_pages()
            if p.status is not None and not p.soft_404 and p.status != 404 and p.url in wanted
        ]

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        pages = self.api_pages(ctx)
        if not pages:
            result.not_assessed_reason = "no API paths responded"
            return result
        for page in pages:
            result.findings.extend(self._document(ctx, page))
        result.findings.extend(await self._graphql(ctx, pages))
        cors = ctx.results.get("CORSGoblin")
        if cors and any(f.status in (Status.ISSUE, Status.MANUAL_CHECK) for f in cors.findings):
            ids = ", ".join(
                f.finding_id
                for f in cors.findings
                if f.status in (Status.ISSUE, Status.MANUAL_CHECK)
            )
            result.findings.append(
                self.finding(
                    title="CORS results for API paths",
                    status=Status.OBSERVATION,
                    affected_url=pages[0].url,
                    observed=f"See CORSGoblin {ids}",
                    why_it_matters="Reported once, under CORSGoblin.",
                )
            )
        if not result.findings:
            result.findings.append(
                self.finding(
                    title="API paths",
                    status=Status.OK,
                    affected_url=pages[0].url,
                    observed=", ".join(f"{p.url} {p.status}" for p in pages),
                    why_it_matters="Check passed.",
                )
            )
        return result

    def _document(self, ctx: TargetContext, page: Page) -> list[Finding]:
        url = page.final_url or page.url
        reproduce = [ctx.curl(url, "-s") + " | head -c 600"]
        out: list[Finding] = []
        data = as_json(page) if page.ok else None
        summary = openapi_summary(data)
        if summary:
            authenticated = bool(ctx.settings.cookie)
            out.append(
                self.finding(
                    title="API specification reachable"
                    + ("" if authenticated else " without authentication"),
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=summary,
                    why_it_matters=(
                        "Lists every endpoint and parameter, which speeds up testing for "
                        "anyone. Not a problem if the API is meant to be public."
                    ),
                    remediation="Restrict API documentation to authorised users if it is internal.",
                    reproduce=reproduce,
                    manual_steps=[
                        "Import the specification into Burp or Postman and test each endpoint "
                        "for authentication and authorisation."
                    ],
                )
            )
        elif page.ok and page.is_html and "swagger-ui" in page.text.lower():
            out.append(
                self.finding(
                    title="Swagger UI reachable",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=f"Status {page.status}, Swagger UI page",
                    why_it_matters="Interactive API documentation is public.",
                    reproduce=[ctx.curl(url, "-s") + " | grep -io swagger-ui | head -1"],
                    manual_steps=["Open it and note the specification URL it loads."],
                )
            )
        elif page.ok and page.is_html and "graphiql" in page.text.lower():
            out.append(
                self.finding(
                    title="GraphiQL IDE reachable",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=f"Status {page.status}, GraphiQL page",
                    why_it_matters="An interactive GraphQL console is public.",
                    reproduce=[ctx.curl(url, "-s") + " | grep -io graphiql | head -1"],
                )
            )
        if isinstance(data, dict) and not summary:
            versions = {k: v for k, v in data.items() if k.lower() in VERSION_KEYS and v}
            if versions:
                shown = ", ".join(f"{k}: {v}" for k, v in versions.items())
                out.append(
                    self.finding(
                        title="API discloses its version",
                        status=Status.OBSERVATION,
                        affected_url=url,
                        observed=shown[:200],
                        why_it_matters="Version details help match the API to known issues.",
                        reproduce=reproduce,
                    )
                )
        if data is None:
            data = as_json(page)
        keys = error_keys(data) if data is not None else []
        if keys:
            out.append(
                self.finding(
                    title="Verbose API error body",
                    status=Status.ISSUE,
                    affected_url=url,
                    observed=f"Status {page.status}, JSON keys: {', '.join(sorted(set(keys)))}",
                    why_it_matters="Error responses include stack or exception detail.",
                    remediation="Return generic error bodies and log the detail server side.",
                    reproduce=reproduce,
                )
            )
        return out

    async def _graphql(self, ctx: TargetContext, pages: list[Page]) -> list[Finding]:
        graphql = [p for p in pages if httpx.URL(p.url).path == "/graphql"]
        if not graphql:
            return []
        url = f"{graphql[0].url}?query={quote(INTROSPECTION)}"
        reproduce = [ctx.curl(url, "-s", "-g")]
        page = await ctx.fetch(url, self.name, follow_redirects=False)
        if page.status is None:
            return [self.not_assessed(url, "GraphQL introspection", page.error or "no response")]
        data = as_json(page)
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            schema = data["data"].get("__schema")
            if schema:
                return [
                    self.finding(
                        title="GraphQL introspection enabled",
                        status=Status.ISSUE,
                        affected_url=graphql[0].url,
                        observed=f"GET introspection returned the schema "
                        f"(query type {schema.get('queryType', {}).get('name')})",
                        expected="Introspection disabled in production",
                        why_it_matters="Anyone can download the full schema: every query, "
                        "mutation and field.",
                        remediation="Disable introspection in production.",
                        reproduce=reproduce,
                        manual_steps=[
                            "Run a full introspection query in Burp and review the schema for "
                            "sensitive queries and mutations."
                        ],
                    )
                ]
        text = page.text.lower()
        if page.status in (400, 405) and ("get" in text or "method" in text or "post" in text):
            return [
                self.not_assessed(
                    graphql[0].url, "GraphQL introspection", "server rejects GET queries"
                )
            ]
        if isinstance(data, dict) and data.get("errors"):
            return [
                self.finding(
                    title="GraphQL introspection disabled",
                    status=Status.OK,
                    affected_url=graphql[0].url,
                    observed=str(data["errors"])[:200],
                    why_it_matters="Check passed.",
                )
            ]
        return [
            self.not_assessed(
                graphql[0].url,
                "GraphQL introspection",
                f"unexpected response (status {page.status})",
            )
        ]

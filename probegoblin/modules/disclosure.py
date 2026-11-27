"""DisclosureGoblin: exposed files, tech-specific paths, error pages, source maps, security.txt."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache

import httpx

from probegoblin.core import datafiles
from probegoblin.core.context import TargetContext
from probegoblin.core.findings import merge_across_pages
from probegoblin.core.models import Finding, ModuleResult, Page, Status
from probegoblin.core.registry import Goblin
from probegoblin.core.secrets import redact_text

READ_BYTES = 4096
MAP_BYTES = 1024
MAX_SOURCE_MAPS = 10
ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,})\s*=(.*)$", re.M)


@dataclass
class Check:
    title: str
    status: Status
    why: str
    fix: str
    detail: str = ""


def _text(page: Page) -> str:
    return page.text


def _json(page: Page):
    try:
        return json.loads(page.body)
    except (ValueError, UnicodeDecodeError):
        return None


def redact_env(text: str) -> str:
    return ENV_LINE.sub(lambda m: f"{m.group(1)}={m.group(2).strip()[:4]}...", text)


def excerpt(page: Page, limit: int = 300) -> str:
    text = page.body[:limit].decode("utf-8", "replace")
    text = redact_text(redact_env(text))
    text = "".join(ch if ch.isprintable() or ch in "\n\t" else "." for ch in text)
    return text.strip()


# Confirmation rules: return a Check when the content proves the exposure, else None.


def c_git(page: Page) -> Check | None:
    text = _text(page).strip()
    if text.startswith("ref: refs/") or re.fullmatch(r"[0-9a-f]{40}", text):
        return Check(
            "Git repository exposed",
            Status.ISSUE,
            "The .git directory is served, so source code and history can usually be rebuilt.",
            "Block access to /.git at the web server and remove it from the web root.",
            text[:60],
        )
    return None


def c_env(page: Page) -> Check | None:
    if page.is_html:
        return None
    lines = ENV_LINE.findall(_text(page))
    if len(lines) >= 2:
        names = ", ".join(name for name, _ in lines[:8])
        return Check(
            ".env file exposed",
            Status.ISSUE,
            "Environment files usually hold database passwords, API keys and app secrets.",
            "Remove .env from the web root, block dotfiles, and rotate every secret in it.",
            f"{len(lines)} KEY=value lines: {names}",
        )
    return None


def c_ds_store(page: Page) -> Check | None:
    if page.body.startswith(b"\x00\x00\x00\x01Bud1"):
        return Check(
            ".DS_Store file exposed",
            Status.ISSUE,
            "macOS folder metadata lists file and folder names in the directory.",
            "Delete .DS_Store files from the web root and block dotfiles.",
        )
    return None


def _marker(title: str, markers: list[str], why: str, fix: str) -> Callable[[Page], Check | None]:
    def rule(page: Page) -> Check | None:
        text = _text(page)
        if any(m.lower() in text.lower() for m in markers):
            return Check(title, Status.ISSUE, why, fix)
        return None

    return rule


def c_phpinfo(page: Page) -> Check | None:
    text = _text(page)
    if "phpinfo()" in text or ("PHP Version" in text and "PHP License" in text):
        version = re.search(r"PHP Version\s*(?:</[^>]+>\s*<[^>]+>)?\s*([\d.]+)", text)
        return Check(
            "phpinfo() page exposed",
            Status.ISSUE,
            "Shows the PHP version, configuration, loaded modules, paths and environment.",
            "Remove the file from production.",
            f"PHP {version.group(1)}" if version else "",
        )
    return None


def c_web_config(page: Page) -> Check | None:
    if "<configuration" in _text(page) and not page.is_html:
        return Check(
            "web.config exposed",
            Status.ISSUE,
            "IIS configuration can contain connection strings and machine keys.",
            "Block access to web.config (IIS blocks it by default).",
        )
    return None


def c_crossdomain(page: Page) -> Check | None:
    text = _text(page)
    if "<cross-domain-policy" not in text:
        return None
    if re.search(r"<allow-access-from[^>]+domain=[\"']\*[\"']", text):
        return Check(
            "crossdomain.xml allows any domain",
            Status.ISSUE,
            "Flash and some legacy clients would let any site read responses.",
            "Restrict allow-access-from to trusted domains, or remove the file.",
        )
    return Check(
        "crossdomain.xml present",
        Status.OBSERVATION,
        "Restricted policy; listed domains are trusted by legacy clients.",
        "Remove the file if nothing uses it.",
        excerpt(page, 200),
    )


def c_clientaccess(page: Page) -> Check | None:
    text = _text(page)
    if "<access-policy" not in text:
        return None
    if re.search(r"<domain[^>]+uri=[\"']\*[\"']", text):
        return Check(
            "clientaccesspolicy.xml allows any domain",
            Status.ISSUE,
            "Silverlight clients from any site could read responses.",
            "Restrict the policy to trusted domains, or remove the file.",
        )
    return Check(
        "clientaccesspolicy.xml present",
        Status.OBSERVATION,
        "Restricted policy.",
        "Remove the file if nothing uses it.",
    )


def c_zip(page: Page) -> Check | None:
    if page.body.startswith(b"PK\x03\x04"):
        size = page.header("content-length")
        return Check(
            "Backup archive downloadable",
            Status.ISSUE,
            "Archives in the web root often contain source code or data.",
            "Remove backup files from the web root.",
            f"ZIP signature confirmed (first 4 KB read only){f', {size} bytes' if size else ''}",
        )
    return None


def c_wp_users(page: Page) -> Check | None:
    data = _json(page)
    if isinstance(data, list) and data and all(isinstance(u, dict) for u in data):
        slugs = [
            str(u.get("slug") or u.get("name")) for u in data if u.get("slug") or u.get("name")
        ]
        if slugs:
            return Check(
                "WordPress users listed by the REST API",
                Status.ISSUE,
                "Usernames help password guessing against wp-login.php and XML-RPC.",
                "Restrict /wp-json/wp/v2/users to authenticated users.",
                f"{len(slugs)} users in the first 4 KB: {', '.join(slugs[:3])}",
            )
    return None


def c_xmlrpc(page: Page) -> Check | None:
    if "XML-RPC server accepts POST requests only" in _text(page):
        return Check(
            "WordPress XML-RPC enabled",
            Status.OBSERVATION,
            "XML-RPC allows many login attempts per request and pingbacks. Not tested (POST).",
            "Disable XML-RPC if it is not used.",
        )
    return None


def c_php_log(page: Page) -> Check | None:
    if re.search(r"PHP (Fatal error|Warning|Notice|Deprecated|Parse error)", _text(page)):
        return Check(
            "WordPress debug log exposed",
            Status.ISSUE,
            "PHP logs reveal file paths, plugin names and sometimes data.",
            "Set WP_DEBUG_LOG off or move the log outside the web root.",
        )
    return None


def c_drupal_changelog(page: Page) -> Check | None:
    match = re.search(r"Drupal (\d+\.\d+(?:\.\d+)?)", _text(page))
    if match and not page.is_html:
        return Check(
            "Drupal changelog exposes the version",
            Status.ISSUE,
            "The exact Drupal version can be matched against known vulnerabilities.",
            "Block or remove CHANGELOG.txt.",
            f"Drupal {match.group(1)}",
        )
    return None


def c_joomla_manifest(page: Page) -> Check | None:
    match = re.search(r"<version>([\d.]+)</version>", _text(page))
    if match and "joomla" in _text(page).lower():
        return Check(
            "Joomla manifest exposes the version",
            Status.ISSUE,
            "The exact Joomla version can be matched against known vulnerabilities.",
            "Block access to /administrator/manifests/.",
            f"Joomla {match.group(1)}",
        )
    return None


def c_actuator_index(page: Page) -> Check | None:
    data = _json(page)
    if isinstance(data, dict) and isinstance(data.get("_links"), dict):
        names = sorted(k for k in data["_links"] if k != "self")
        return Check(
            "Spring Boot Actuator endpoints exposed",
            Status.ISSUE,
            "Actuator endpoints can reveal configuration, environment, mappings and heap dumps.",
            "Expose only health (without details) and require authentication for the rest.",
            f"Endpoints: {', '.join(names[:15])}",
        )
    return None


def c_actuator_health(page: Page) -> Check | None:
    data = _json(page)
    if isinstance(data, dict) and "status" in data:
        detailed = "components" in data or "details" in data
        return Check(
            "Spring Boot health endpoint" + (" shows component details" if detailed else ""),
            Status.ISSUE if detailed else Status.OBSERVATION,
            (
                "Component details reveal databases, disk and downstream services."
                if detailed
                else "Health status only. Common and usually intended."
            ),
            "Set management.endpoint.health.show-details=never for anonymous users.",
            f"status {data.get('status')}" + (", component details present" if detailed else ""),
        )
    return None


def c_actuator_env(page: Page) -> Check | None:
    data = _json(page)
    text = _text(page)
    if (isinstance(data, dict) and "propertySources" in data) or '"propertySources"' in text:
        return Check(
            "Spring Boot environment endpoint exposed",
            Status.ISSUE,
            "/actuator/env lists configuration properties, which can include credentials.",
            "Disable or protect the env endpoint.",
        )
    return None


def c_heapdump(page: Page) -> Check | None:
    ctype = page.content_type
    if (
        page.status == 200
        and not page.is_html
        and ("octet-stream" in ctype or "hprof" in ctype or not ctype)
    ):
        size = page.header("content-length")
        return Check(
            "Spring Boot heap dump downloadable",
            Status.ISSUE,
            "A heap dump holds memory contents: sessions, credentials and keys. Checked with "
            "HEAD only, nothing was downloaded.",
            "Disable the heapdump endpoint.",
            f"HEAD 200, Content-Type {ctype or 'none'}" + (f", {size} bytes" if size else ""),
        )
    return None


def c_ignition(page: Page) -> Check | None:
    data = _json(page)
    if isinstance(data, dict) and "can_execute_commands" in data:
        return Check(
            "Laravel Ignition exposed",
            Status.ISSUE,
            "Ignition runs in debug mode. Older Ignition versions are affected by "
            "CVE-2021-3129 (remote code execution).",
            "Set APP_DEBUG=false and remove Ignition from production.",
            f"can_execute_commands: {data['can_execute_commands']}",
        )
    return None


def c_laravel_log(page: Page) -> Check | None:
    if re.search(
        r"^\[\d{4}-\d{2}-\d{2}[ T][\d:]+\] \w+\.(ERROR|INFO|WARNING|DEBUG)", _text(page), re.M
    ):
        return Check(
            "Laravel log file exposed",
            Status.ISSUE,
            "Application logs reveal stack traces, paths and sometimes data or secrets.",
            "Serve only the public directory, never storage/.",
        )
    return None


def c_status_only(page: Page) -> Check | None:
    if page.status in (200, 401, 403):
        meaning = {
            200: "reachable without credentials",
            401: "present and asks for credentials",
            403: "present but blocked",
        }[page.status]
        return Check(
            "Tomcat Manager present",
            Status.ISSUE if page.status == 200 else Status.OBSERVATION,
            f"The manager application is {meaning}. It can deploy code.",
            "Remove the manager application or restrict it to admin networks.",
            f"Status {page.status} (status recorded only)",
        )
    return None


RULES: dict[str, Callable[[Page], Check | None]] = {
    "git": c_git,
    "env": c_env,
    "ds_store": c_ds_store,
    "server_status": _marker(
        "Apache server-status exposed",
        ["Apache Server Status for"],
        "Lists current requests, client IPs and URLs being served.",
        "Restrict /server-status to localhost or admin networks.",
    ),
    "server_info": _marker(
        "Apache server-info exposed",
        ["Apache Server Information"],
        "Shows the full Apache configuration and modules.",
        "Disable mod_info or restrict it.",
    ),
    "phpinfo": c_phpinfo,
    "web_config": c_web_config,
    "crossdomain": c_crossdomain,
    "clientaccess": c_clientaccess,
    "zip": c_zip,
    "wp_users": c_wp_users,
    "xmlrpc": c_xmlrpc,
    "php_log": c_php_log,
    "drupal_changelog": c_drupal_changelog,
    "joomla_manifest": c_joomla_manifest,
    "actuator_index": c_actuator_index,
    "actuator_health": c_actuator_health,
    "actuator_env": c_actuator_env,
    "heapdump": c_heapdump,
    "ignition": c_ignition,
    "telescope": _marker(
        "Laravel Telescope exposed",
        ["Laravel Telescope", "telescope-app"],
        "Telescope shows requests, queries, exceptions and logs.",
        "Restrict Telescope to local environments or authorised users.",
    ),
    "laravel_log": c_laravel_log,
    "symfony_profiler": _marker(
        "Symfony profiler exposed",
        ["Symfony Profiler", "sf-toolbar"],
        "The profiler records requests, headers, cookies and database queries.",
        "Disable the profiler in production.",
    ),
    "symfony_dev": _marker(
        "Symfony development front controller exposed",
        ["sf-toolbar", "Symfony Exception", "Symfony\\Component"],
        "The dev environment runs with debug output and the profiler.",
        "Remove app_dev.php from production.",
    ),
    "elmah": _marker(
        "ELMAH error log exposed",
        ["Error Log for"],
        "ELMAH lists exceptions with request details, often including cookies.",
        "Restrict elmah.axd to administrators (allowRemoteAccess=false).",
    ),
    "trace_axd": _marker(
        "ASP.NET trace viewer exposed",
        ["Application Trace"],
        "Trace output includes request details, headers, cookies and session state.",
        'Disable tracing (<trace enabled="false">).',
    ),
    "status_only": c_status_only,
}

GENERIC: dict[str, str] = {
    "/.git/HEAD": "git",
    "/.env": "env",
    "/.DS_Store": "ds_store",
    "/server-status": "server_status",
    "/server-info": "server_info",
    "/phpinfo.php": "phpinfo",
    "/info.php": "phpinfo",
    "/web.config": "web_config",
    "/crossdomain.xml": "crossdomain",
    "/clientaccesspolicy.xml": "clientaccess",
    "/backup.zip": "zip",
    "/site.zip": "zip",
}
SECURITY_TXT = ("/.well-known/security.txt", "/security.txt")

ERROR_SIGNS: list[tuple[str, re.Pattern, Status, str]] = [
    (
        "Directory listing enabled",
        re.compile(r"<title>\s*Index of /|<h1>Directory listing for /", re.I),
        Status.ISSUE,
        "Directory contents are listed, exposing file names.",
    ),
    (
        "Django debug page",
        re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>"),
        Status.ISSUE,
        "Debug mode shows settings, paths and source code.",
    ),
    (
        "Laravel or Whoops debug page",
        re.compile(r"Whoops, looks like something went wrong|ignition-|class=\"exception_title\""),
        Status.ISSUE,
        "Debug error pages show source code, environment and stack traces.",
    ),
    (
        "ASP.NET detailed error page",
        re.compile(r"Server Error in '[^']*' Application|<b> Stack Trace: </b>"),
        Status.ISSUE,
        "Detailed errors show stack traces and source lines.",
    ),
    (
        "Java stack trace",
        re.compile(r"\bat [\w$.]+\([\w$]+\.java:\d+\)|Exception in thread \""),
        Status.ISSUE,
        "Stack traces reveal classes, libraries and internal structure.",
    ),
    (
        "Python traceback",
        re.compile(r"Traceback \(most recent call last\):"),
        Status.ISSUE,
        "Tracebacks reveal source paths and code.",
    ),
    (
        "PHP error output",
        re.compile(
            r"<b>(Fatal error|Warning|Parse error|Notice)</b>:.{0,200}? in <b>/|Stack trace:\s*#0",
            re.S,
        ),
        Status.ISSUE,
        "PHP errors reveal file paths and code structure.",
    ),
    (
        "Node.js stack trace",
        re.compile(r"\n\s+at [\w.<>]+ \((?:/|[A-Z]:\\)[^)]+\.js:\d+:\d+\)"),
        Status.ISSUE,
        "Stack traces reveal file paths and modules.",
    ),
    (
        "Rails error page",
        re.compile(r"Action Controller: Exception caught|ActionController::RoutingError"),
        Status.ISSUE,
        "Rails debug pages reveal routes and source.",
    ),
    (
        "Spring Whitelabel error page",
        re.compile(r"Whitelabel Error Page"),
        Status.OBSERVATION,
        "Identifies Spring Boot. No stack trace by itself.",
    ),
    (
        "Internal file path in response",
        re.compile(
            r"(/var/www/|/home/\w+/|/usr/local/\w+/|/opt/\w+/|[CD]:\\(?:inetpub|Users|Windows)\\)"
        ),
        Status.OBSERVATION,
        "Server file paths help an attacker map the system.",
    ),
    (
        "Default server page",
        re.compile(
            r"Welcome to nginx!|Apache2 (Ubuntu|Debian) Default Page|<h1>It works!</h1>|"
            r"<title>IIS Windows Server</title>|Test Page for the Apache HTTP Server",
        ),
        Status.OBSERVATION,
        "A default install page suggests an unconfigured or forgotten virtual host.",
    ),
]


@lru_cache(maxsize=1)
def path_packs() -> list[dict]:
    text = datafiles.read_text("path_packs.toml")
    return tomllib.loads(text).get("pack", [])


def parse_security_txt(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-----"):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    return fields


class DisclosureGoblin(Goblin):
    name = "DisclosureGoblin"
    flag = "disclosure"
    prefix = "DSC"
    order = 100
    description = "Exposed files, tech path packs, error pages, source maps, security.txt"

    def estimate_requests(self, settings) -> int:
        packs = max(len(p["paths"]) for p in path_packs()) * 2
        return len(settings.disclosure_paths) + packs + MAX_SOURCE_MAPS

    def plan(self, ctx: TargetContext) -> list[tuple[str, str, str, str | None]]:
        """(path, method, rule, title) to request."""
        plan: list[tuple[str, str, str, str | None]] = []
        for path in ctx.settings.disclosure_paths:
            if path in SECURITY_TXT:
                continue
            plan.append((path, "GET", GENERIC.get(path, ""), None))
        haystack = "\n".join(
            p.text[:20000] + "\n".join(f"{k}: {v}" for k, v in p.headers)
            for p in ctx.store.all_pages()
            if p.status
        )
        for pack in path_packs():
            hit = any(ctx.has_tech(t) for t in pack.get("tech", []))
            hit = hit or any(m in haystack for m in pack.get("markers", []))
            if not hit:
                continue
            for entry in pack["paths"]:
                plan.append(
                    (entry["path"], entry.get("method", "GET"), entry["check"], entry.get("title"))
                )
        return plan

    async def run(self, ctx: TargetContext) -> ModuleResult:
        result = self.result()
        root = httpx.URL(ctx.target).copy_with(path="/", query=None)
        dot_baseline = next((b.status for b in ctx.store.baselines if "/." in b.url), None)
        for path, method, rule, _title in self.plan(ctx):
            url = str(root.join(path))
            page = await ctx.fetch(url, self.name, method, max_bytes=READ_BYTES)
            finding = self._assess_path(ctx, url, method, page, rule, dot_baseline)
            if finding:
                result.findings.append(finding)
        result.findings.extend(await self._security_txt(ctx, root))
        result.findings.extend(await self._source_maps(ctx))
        result.findings.extend(merge_across_pages(self._scan_store(ctx)))
        return result

    def _assess_path(
        self,
        ctx: TargetContext,
        url: str,
        method: str,
        page: Page,
        rule: str,
        dot_baseline: int | None,
    ) -> Finding | None:
        if method == "HEAD":
            reproduce = [ctx.curl(url, "-sI")]
        else:
            reproduce = [ctx.curl(url, "-s", "-r 0-1023") + " | head -c 400"]
        if page.status is None:
            return None
        if page.soft_404 and rule != "status_only":
            return None
        if rule == "status_only":
            check = c_status_only(page)
        elif rule in RULES and page.status < 400:
            check = RULES[rule](page)
        elif not rule and page.ok:
            check = Check(
                f"{httpx.URL(url).path} responded",
                Status.MANUAL_CHECK,
                "A configured disclosure path returned content that differs from the "
                "not-found baseline. Content was not confirmed.",
                "Remove the file if it should not be public.",
            )
        else:
            check = None
        if check:
            observed = f"{method} {page.status}, {page.content_type or 'no content type'}"
            observed += f", {len(page.body)} bytes read"
            if check.detail:
                observed += f"\n{check.detail}"
            elif method != "HEAD" and page.body:
                observed += f"\nExcerpt: {excerpt(page, 200)}"
            return self.finding(
                title=check.title,
                status=check.status,
                affected_url=url,
                observed=observed,
                why_it_matters=check.why,
                remediation=check.fix,
                reproduce=reproduce,
                manual_steps=(
                    [
                        "Confirm the content in Burp. Do not download whole files unless the "
                        "engagement allows it."
                    ]
                    if check.status in (Status.ISSUE, Status.MANUAL_CHECK)
                    else []
                ),
            )
        path = httpx.URL(url).path
        if (
            page.status == 403
            and path.split("/")[-1].startswith(".")
            and dot_baseline is not None
            and dot_baseline != 403
        ):
            return self.finding(
                title=f"{path} exists but is forbidden",
                status=Status.OBSERVATION,
                affected_url=url,
                observed=f"403 here, {dot_baseline} for a random dotfile",
                why_it_matters="The different status suggests the file exists. Access is blocked.",
                reproduce=reproduce,
            )
        return None

    async def _security_txt(self, ctx: TargetContext, root: httpx.URL) -> list[Finding]:
        found: Page | None = None
        url = str(root.join(SECURITY_TXT[0]))
        for path in SECURITY_TXT:
            candidate_url = str(root.join(path))
            page = await ctx.fetch(candidate_url, self.name, max_bytes=READ_BYTES)
            if page.ok and not page.is_html and "contact:" in page.text.lower():
                found, url = page, candidate_url
                break
        if found is None:
            return [
                self.finding(
                    title="security.txt not present",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed="No security.txt at /.well-known/security.txt or /security.txt",
                    why_it_matters="Researchers have no published way to report vulnerabilities.",
                    remediation="Publish /.well-known/security.txt (RFC 9116).",
                    references=["https://www.rfc-editor.org/rfc/rfc9116"],
                )
            ]
        fields = parse_security_txt(found.text)
        problems: list[str] = []
        if not fields.get("contact"):
            problems.append("no Contact")
        expires = fields.get("expires", [])
        if not expires:
            problems.append("no Expires (required)")
        else:
            try:
                when = datetime.fromisoformat(expires[0].replace("Z", "+00:00"))
                if when.tzinfo is None:
                    when = when.replace(tzinfo=UTC)
                if when < datetime.now(UTC):
                    problems.append(f"expired on {expires[0]}")
            except ValueError:
                problems.append(f"Expires is not an RFC 3339 date ({expires[0]})")
            if len(expires) > 1:
                problems.append("Expires appears more than once")
        if SECURITY_TXT[0] not in url:
            problems.append("served at /security.txt instead of /.well-known/security.txt")
        summary = "\n".join(
            f"{key.title()}: {', '.join(values)}"
            for key, values in fields.items()
            if key in ("contact", "expires", "policy", "canonical", "encryption")
        )
        if problems:
            return [
                self.finding(
                    title="security.txt has problems",
                    status=Status.OBSERVATION,
                    affected_url=url,
                    observed=f"{'; '.join(problems)}\n{summary}",
                    why_it_matters="Clients may ignore or distrust an incomplete or expired file.",
                    remediation="Follow RFC 9116: Contact and Expires are required.",
                    reproduce=[ctx.curl(url, "-s")],
                    references=["https://www.rfc-editor.org/rfc/rfc9116"],
                )
            ]
        return [
            self.finding(
                title="security.txt",
                status=Status.OK,
                affected_url=url,
                observed=summary,
                why_it_matters="Check passed.",
            )
        ]

    async def _source_maps(self, ctx: TargetContext) -> list[Finding]:
        out: list[Finding] = []
        for url in ctx.store.source_maps[:MAX_SOURCE_MAPS]:
            if not ctx.client.scope.is_target(httpx.URL(url)):
                continue
            page = await ctx.fetch(url, self.name, max_bytes=MAP_BYTES)
            if not page.ok or page.is_html:
                continue
            text = page.text
            if '"version"' in text and ('"mappings"' in text or '"sources"' in text):
                sources = re.findall(r'"sources"\s*:\s*\[\s*"([^"]+)"', text)
                out.append(
                    self.finding(
                        title="JavaScript source map publicly accessible",
                        status=Status.ISSUE,
                        affected_url=url,
                        observed="Source map JSON confirmed in the first 1 KB"
                        + (f"\nFirst source: {sources[0]}" if sources else ""),
                        why_it_matters=(
                            "Source maps rebuild the original source, including comments, "
                            "internal routes and file structure."
                        ),
                        remediation="Do not deploy .map files, or restrict them to internal users.",
                        reproduce=[ctx.curl(url, "-s", "-r 0-1023")],
                    )
                )
        return out

    def _scan_store(self, ctx: TargetContext) -> list[Finding]:
        out: list[Finding] = []
        pages = sorted(ctx.store.all_pages(), key=lambda p: p.source == "baseline")
        for page in pages:
            if page.status is None or "static" in page.tags or "api_docs" in page.tags:
                continue
            if page.source == "js" or page.content_type.endswith("javascript"):
                continue
            text = page.text
            for title, pattern, status, why in ERROR_SIGNS:
                match = pattern.search(text)
                if not match:
                    continue
                start = max(0, match.start() - 60)
                snippet = redact_text(" ".join(text[start : match.end() + 80].split()))[:220]
                out.append(
                    self.finding(
                        title=title,
                        status=status,
                        affected_url=page.url,
                        observed=f"Status {page.status}: ...{snippet}...",
                        why_it_matters=why,
                        remediation=(
                            "Turn off debug output and use generic error pages."
                            if status == Status.ISSUE
                            else None
                        ),
                        reproduce=[ctx.curl(page.url, "-s") + f" | grep -c {_grep_word(title)}"],
                    )
                )
        return out


def _grep_word(title: str) -> str:
    words = {
        "Directory listing enabled": "'Index of'",
        "Django debug page": "'DEBUG = True'",
        "Laravel or Whoops debug page": "-iE 'whoops|ignition'",
        "ASP.NET detailed error page": "'Server Error in'",
        "Java stack trace": "-E '\\.java:[0-9]+\\)'",
        "Python traceback": "'Traceback'",
        "PHP error output": "-E 'Fatal error|Stack trace'",
        "Node.js stack trace": "-E '\\.js:[0-9]+:[0-9]+\\)'",
        "Rails error page": "'Action Controller'",
        "Spring Whitelabel error page": "'Whitelabel Error Page'",
        "Internal file path in response": "-E '/var/www/|/home/|inetpub'",
        "Default server page": "-iE 'welcome to nginx|default page|it works'",
    }
    return words.get(title, "''")

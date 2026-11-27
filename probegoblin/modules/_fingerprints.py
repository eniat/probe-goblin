"""Python matcher for the webappanalyzer fingerprint set (enthec/webappanalyzer, GPL-3.0)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from probegoblin.core import datafiles
from probegoblin.core.cookies import parse_set_cookie
from probegoblin.core.discovery import PageStore

HTML_SCAN_BYTES = 512 * 1024
VERSION_RE = re.compile(r"^\d+(\.\d+)*[\w.+-]*$")


@dataclass
class Pattern:
    regex: re.Pattern | None
    version: str | None = None
    confidence: int = 100

    def match(self, value: str) -> tuple[bool, str | None]:
        if self.regex is None:
            return True, None
        found = self.regex.search(value)
        if not found:
            return False, None
        return True, resolve_version(self.version, found) if self.version else None


@dataclass
class Fingerprint:
    name: str
    categories: list[int]
    cpe: str | None
    headers: dict[str, list[Pattern]] = field(default_factory=dict)
    cookies: dict[str, list[Pattern]] = field(default_factory=dict)
    meta: dict[str, list[Pattern]] = field(default_factory=dict)
    html: list[Pattern] = field(default_factory=list)
    text: list[Pattern] = field(default_factory=list)
    script_src: list[Pattern] = field(default_factory=list)
    scripts: list[Pattern] = field(default_factory=list)
    url: list[Pattern] = field(default_factory=list)
    robots: list[Pattern] = field(default_factory=list)
    implies: list[tuple[str, int]] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    requires_category: list[int] = field(default_factory=list)
    browser_only: bool = False
    js: dict[str, list[Pattern]] = field(default_factory=dict)
    dom: list[DomCheck] = field(default_factory=list)


@dataclass
class DomCheck:
    selector: str
    attributes: dict[str, list[Pattern]] = field(default_factory=dict)
    properties: dict[str, list[Pattern]] = field(default_factory=dict)
    text: list[Pattern] = field(default_factory=list)


@dataclass
class Detection:
    name: str
    version: str | None = None
    confidence: int = 0
    evidence: list[str] = field(default_factory=list)
    implied_by: str | None = None


def resolve_version(template: str, found: re.Match) -> str | None:
    def group(number: int) -> str:
        if number > (found.re.groups or 0):
            return ""
        return found.group(number) or ""

    def ternary(m: re.Match) -> str:
        return m.group(2) if group(int(m.group(1))) else m.group(3)

    value = re.sub(r"\\(\d+)\?([^:]*):(.*)", ternary, template)
    value = re.sub(r"\\(\d+)", lambda m: group(int(m.group(1))), value).strip()
    return value if value and VERSION_RE.match(value) else None


def parse_pattern(raw: str) -> Pattern | None:
    parts = str(raw).split("\\;")
    pattern = Pattern(regex=None)
    for extra in parts[1:]:
        key, _, value = extra.partition(":")
        if key == "version":
            pattern.version = value
        elif key == "confidence" and value.isdigit():
            pattern.confidence = int(value)
    if parts[0]:
        try:
            pattern.regex = re.compile(parts[0], re.I)
        except (re.error, OverflowError):
            return None
    return pattern


def _patterns(value) -> list[Pattern]:
    values = value if isinstance(value, list) else [value]
    return [p for p in (parse_pattern(v) for v in values if isinstance(v, str)) if p]


def _keyed(value) -> dict[str, list[Pattern]]:
    if not isinstance(value, dict):
        return {}
    return {key.lower(): _patterns(raw) for key, raw in value.items()}


def _names(value) -> list[str]:
    values = value if isinstance(value, list) else [value] if value else []
    return [str(v).split("\\;")[0] for v in values]


def _dom(value) -> list[DomCheck]:
    checks: list[DomCheck] = []
    if isinstance(value, str):
        value = [value]
    if isinstance(value, list):
        for raw in value:
            if isinstance(raw, str):
                checks.append(DomCheck(selector=raw.split("\\;")[0]))
    elif isinstance(value, dict):
        for selector, spec in value.items():
            check = DomCheck(selector=selector)
            if isinstance(spec, dict):
                check.attributes = _keyed_raw(spec.get("attributes"))
                check.properties = _keyed_raw(spec.get("properties"))
                if spec.get("text") is not None:
                    check.text = _patterns(spec["text"])
            checks.append(check)
    return checks


def _keyed_raw(value) -> dict[str, list[Pattern]]:
    if not isinstance(value, dict):
        return {}
    return {key: _patterns(raw) for key, raw in value.items()}


def data_dir() -> Path:
    """User data from `probegoblin update` when valid, otherwise the bundled copy."""
    user = datafiles.user_data() / "webappanalyzer"
    if (user / "technologies").is_dir() and (user / "categories.json").is_file():
        return user
    return datafiles.bundled("webappanalyzer")


@lru_cache(maxsize=1)
def load() -> tuple[list[Fingerprint], dict[int, str]]:
    base = data_dir()
    categories = {
        int(key): value.get("name", key)
        for key, value in json.loads((base / "categories.json").read_text("utf-8")).items()
    }
    fingerprints: list[Fingerprint] = []
    for file in sorted((base / "technologies").glob("*.json")):
        for name, entry in json.loads(file.read_text("utf-8")).items():
            implies = []
            for raw in (
                entry.get("implies", [])
                if isinstance(entry.get("implies"), list)
                else ([entry["implies"]] if entry.get("implies") else [])
            ):
                parsed = parse_pattern(raw)
                implies.append((str(raw).split("\\;")[0], parsed.confidence if parsed else 100))
            fp = Fingerprint(
                name=name,
                categories=[int(c) for c in entry.get("cats", [])],
                cpe=entry.get("cpe"),
                headers=_keyed(entry.get("headers")),
                cookies=_keyed(entry.get("cookies")),
                meta=_keyed(entry.get("meta")),
                html=_patterns(entry.get("html", [])),
                text=_patterns(entry.get("text", [])),
                script_src=_patterns(entry.get("scriptSrc", [])),
                scripts=_patterns(entry.get("scripts", [])),
                url=_patterns(entry.get("url", [])),
                robots=_patterns(entry.get("robots", [])),
                implies=implies,
                excludes=_names(entry.get("excludes")),
                requires=_names(entry.get("requires")),
                requires_category=[int(c) for c in _names(entry.get("requiresCategory"))],
                browser_only=bool(entry.get("js") or entry.get("dom")),
                js=_keyed_raw(entry.get("js")),
                dom=_dom(entry.get("dom")),
            )
            fingerprints.append(fp)
    return fingerprints, categories


@dataclass
class Evidence:
    """Everything the matcher looks at, collected once from the page store."""

    headers: dict[str, list[str]] = field(default_factory=dict)
    cookies: dict[str, list[str]] = field(default_factory=dict)
    meta: dict[str, list[str]] = field(default_factory=dict)
    html: list[str] = field(default_factory=list)
    text: list[str] = field(default_factory=list)
    script_src: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    robots: str = ""
    js: dict[str, list[str]] = field(default_factory=dict)
    dom: dict[str, list[dict]] = field(default_factory=dict)
    browser: bool = False


TAG_RE = re.compile(r"<(script|style)\b.*?</\1>|<[^>]+>", re.I | re.S)


def browser_queries() -> tuple[list[str], list[dict]]:
    """Property chains and DOM queries the browser stage should read for fingerprints."""
    chains: set[str] = set()
    queries: dict[str, dict[str, set[str]]] = {}
    for fp in load()[0]:
        chains.update(fp.js)
        for check in fp.dom:
            entry = queries.setdefault(check.selector, {"attributes": set(), "properties": set()})
            entry["attributes"].update(check.attributes)
            entry["properties"].update(check.properties)
    return sorted(chains), [
        {
            "selector": selector,
            "attributes": sorted(v["attributes"]),
            "properties": sorted(v["properties"]),
        }
        for selector, v in sorted(queries.items())
    ]


def collect(store: PageStore, browser=None) -> Evidence:
    ev = Evidence()
    if browser is not None:
        ev.browser = True
        for page in browser.pages:
            for chain, value in page.js_properties.items():
                ev.js.setdefault(chain, []).append(value)
            for selector, item in page.dom_matches.items():
                ev.dom.setdefault(selector, []).append(item)
            if page.dom:
                ev.html.append(page.dom[:HTML_SCAN_BYTES])
        for script in browser.scripts:
            if script.url not in ev.script_src:
                ev.script_src.append(script.url)
    for page in store.all_pages():
        if page.status is None or page.source == "baseline":
            continue
        hops = page.chain or []
        for hop in hops:
            for key, value in hop.headers:
                ev.headers.setdefault(key.lower(), []).append(value)
                if key.lower() == "set-cookie":
                    parsed = parse_set_cookie(value)
                    if parsed:
                        ev.cookies.setdefault(parsed.name.lower(), []).append(parsed.value)
        if not page.ok:
            continue
        if page.final_url:
            ev.urls.append(page.final_url)
        info = store.html.get(page.url)
        if info is not None:
            html = page.body[:HTML_SCAN_BYTES].decode("utf-8", "replace")
            ev.html.append(html)
            ev.text.append(" ".join(TAG_RE.sub(" ", html).split()))
            for meta in info.metas:
                key = (meta.get("name") or meta.get("property") or "").lower()
                if key and "content" in meta:
                    ev.meta.setdefault(key, []).append(meta["content"])
            ev.script_src.extend(s.src for s in info.scripts)
            ev.scripts.extend(info.inline_scripts)
    for page in store.js:
        ev.scripts.append(page.text)
    for _page, src in store.third_party_scripts:
        if src not in ev.script_src:
            ev.script_src.append(src)
    if store.robots and store.robots.ok and not store.robots.is_html:
        ev.robots = store.robots.text
    return ev


def _check(patterns: list[Pattern], values: list[str]) -> tuple[int, str | None] | None:
    best: tuple[int, str | None] | None = None
    for pattern in patterns:
        for value in values:
            hit, version = pattern.match(value)
            if hit:
                if best is None or (version and not best[1]):
                    best = (pattern.confidence, version)
                if version:
                    return best
                break
    return best


def match(ev: Evidence) -> tuple[list[Detection], bool]:
    """Return detections and whether any fingerprint needed browser data to decide."""
    fingerprints, categories = load()
    found: dict[str, Detection] = {}

    def add(fp: Fingerprint, where: str, result: tuple[int, str | None] | None) -> None:
        if result is None:
            return
        confidence, version = result
        det = found.setdefault(fp.name, Detection(fp.name))
        det.confidence = min(100, det.confidence + confidence)
        if version and not det.version:
            det.version = version
        if where not in det.evidence:
            det.evidence.append(where)

    for fp in fingerprints:
        for name, patterns in fp.headers.items():
            if name in ev.headers:
                add(fp, f"{name} header", _check(patterns, ev.headers[name]))
        for name, patterns in fp.cookies.items():
            if name in ev.cookies:
                add(fp, f"{name} cookie", _check(patterns, ev.cookies[name]) or None)
        for name, patterns in fp.meta.items():
            if name in ev.meta:
                add(fp, f"meta {name}", _check(patterns, ev.meta[name]))
        if fp.script_src:
            add(fp, "script URL", _check(fp.script_src, ev.script_src))
        if fp.url:
            add(fp, "URL", _check(fp.url, ev.urls))
        if fp.robots and ev.robots:
            add(fp, "robots.txt", _check(fp.robots, [ev.robots]))
        if fp.html:
            add(fp, "HTML", _check(fp.html, ev.html))
        if fp.text:
            add(fp, "page text", _check(fp.text, ev.text))
        if fp.scripts:
            add(fp, "script content", _check(fp.scripts, ev.scripts))
        if ev.browser:
            for chain, patterns in fp.js.items():
                if chain in ev.js:
                    add(
                        fp,
                        f"JS {chain}",
                        _check(patterns, ev.js[chain]) if patterns else (100, None),
                    )
            for check in fp.dom:
                items = ev.dom.get(check.selector)
                if not items:
                    continue
                if not (check.attributes or check.properties or check.text):
                    add(fp, "DOM", (100, None))
                    continue
                for name, patterns in check.attributes.items():
                    values = [i["attributes"][name] for i in items if name in i["attributes"]]
                    if values:
                        add(fp, "DOM attribute", _check(patterns, values))
                for name, patterns in check.properties.items():
                    values = [i["properties"][name] for i in items if name in i["properties"]]
                    if values:
                        add(fp, "DOM property", _check(patterns, values))
                if check.text:
                    add(fp, "DOM text", _check(check.text, [i["text"] for i in items]))

    detections = {k: v for k, v in found.items() if v.confidence >= 50}
    by_name = {fp.name: fp for fp in fingerprints}

    # Implied technologies, transitively.
    queue = list(detections)
    while queue:
        name = queue.pop()
        fp = by_name.get(name)
        if fp is None:
            continue
        for implied, confidence in fp.implies:
            if implied not in detections and implied in by_name and confidence >= 50:
                detections[implied] = Detection(implied, confidence=confidence, implied_by=name)
                queue.append(implied)

    for name in list(detections):
        fp = by_name.get(name)
        if fp is None:
            continue
        for excluded in fp.excludes:
            detections.pop(excluded, None)

    present_cats = {c for n in detections for c in by_name[n].categories if n in by_name}
    for name in list(detections):
        fp = by_name[name]
        missing_tech = fp.requires and not any(r in detections for r in fp.requires)
        missing_cat = fp.requires_category and not set(fp.requires_category) & present_cats
        if missing_tech or missing_cat:
            detections.pop(name)

    browser_needed = any(fp.browser_only for fp in fingerprints)
    return sorted(detections.values(), key=lambda d: d.name.lower()), browser_needed


def categories_for(name: str) -> list[str]:
    fingerprints, categories = load()
    for fp in fingerprints:
        if fp.name == name:
            return [categories.get(c, str(c)) for c in fp.categories]
    return []


def cpe_for(name: str) -> str | None:
    for fp in load()[0]:
        if fp.name == name:
            return fp.cpe
    return None

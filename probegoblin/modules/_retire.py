"""Static JS library detection with the RetireJS repository (RetireJS/retire.js, Apache-2.0)."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache

from probegoblin.core import datafiles

VERSION = r"[0-9][0-9.a-z_\-]+"
# RetireJS names that differ from the npm package.
NPM_NAMES = {
    "angularjs": "angular",
    "jquery-ui-dialog": "jquery-ui",
    "jquery-ui-autocomplete": "jquery-ui",
    "jquery-ui-tooltip": "jquery-ui",
    "jquery.prettyPhoto": None,
    "ember": "ember-source",
    "vue": "vue",
    "react": "react",
    "dont check": None,
}
METHODS = {
    "uri": "CDN URL",
    "filename": "filename",
    "filecontent": "version banner",
    "filecontentreplace": "code signature",
    "hashes": "file hash",
}


@dataclass
class StaticHit:
    library: str
    npm: str | None
    version: str
    method: str
    source: str


@dataclass
class Rule:
    library: str
    npm: str | None
    kind: str
    regex: re.Pattern | None
    replacement: str | None = None


def _compile(pattern: str) -> re.Pattern | None:
    try:
        return re.compile(pattern.replace("§§version§§", VERSION))
    except re.error:
        return None


@lru_cache(maxsize=1)
def rules() -> tuple[list[Rule], dict[str, tuple[str, str | None, str]]]:
    data = json.loads(datafiles.read_text("retirejs/jsrepository.json"))
    out: list[Rule] = []
    hashes: dict[str, tuple[str, str | None, str]] = {}
    for library, entry in data.items():
        if library == "retire-example":
            continue
        npm = entry.get("npmname") or NPM_NAMES.get(library, library)
        extractors = entry.get("extractors", {})
        for kind in ("uri", "filename", "filecontent"):
            for pattern in extractors.get(kind, []):
                compiled = _compile(pattern)
                if compiled:
                    out.append(Rule(library, npm, kind, compiled))
        for spec in extractors.get("filecontentreplace", []):
            # Format: /regex/replacement/
            match = re.fullmatch(r"/(.*)/(.*)/", spec)
            if match:
                compiled = _compile(match.group(1))
                if compiled:
                    out.append(Rule(library, npm, "filecontentreplace", compiled, match.group(2)))
        for digest, version in (extractors.get("hashes") or {}).items():
            hashes[digest] = (library, npm, version)
    return out, hashes


def validate(text: str) -> None:
    data = json.loads(text)
    if not isinstance(data, dict) or "jquery" not in data:
        raise ValueError("not a RetireJS repository")
    for entry in data.values():
        if not isinstance(entry, dict) or "extractors" not in entry:
            raise ValueError("entry without extractors")


def scan_url(url: str) -> list[StaticHit]:
    hits = []
    filename = url.split("?")[0].rsplit("/", 1)[-1]
    for rule in rules()[0]:
        if rule.kind == "uri":
            match = rule.regex.search(url)
        elif rule.kind == "filename":
            match = rule.regex.search(filename)
        else:
            continue
        if match and match.groups():
            hits.append(StaticHit(rule.library, rule.npm, match.group(1), METHODS[rule.kind], url))
    return hits


def scan_content(url: str, text: str, raw: bytes | None = None) -> list[StaticHit]:
    hits = []
    sample = text[:400000]
    for rule in rules()[0]:
        if rule.kind == "filecontent":
            match = rule.regex.search(sample)
            if match and match.groups():
                hits.append(
                    StaticHit(rule.library, rule.npm, match.group(1), METHODS[rule.kind], url)
                )
        elif rule.kind == "filecontentreplace":
            match = rule.regex.search(sample)
            if match:
                version = match.expand(rule.replacement.replace("$", "\\"))
                hits.append(StaticHit(rule.library, rule.npm, version, METHODS[rule.kind], url))
    digest = hashlib.sha1(raw if raw is not None else text.encode("utf-8")).hexdigest()
    known = rules()[1].get(digest)
    if known:
        hits.append(StaticHit(known[0], known[1], known[2], METHODS["hashes"], url))
    return hits

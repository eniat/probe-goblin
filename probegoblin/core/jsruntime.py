"""Runtime library expressions: parsed in Python into plain property paths, then walked in the
page by a fixed function. Nothing from the data file is ever executed as code, so a page's CSP
cannot block it and an expression can never call anything."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

import yaml

from probegoblin.core import datafiles

VERSION_RE = re.compile(r"^\d+(\.\d+)*")
_PATH_TOKEN = re.compile(
    r"""\s*(?:\?\.)?(?:\.)?\s*(?:([A-Za-z_$][\w$]*)|\[\s*(?:'([^']*)'|"([^"]*)"|(\d+))\s*\])"""
)
_SELECTOR = re.compile(
    r"""^document\.querySelector\((['"])(.+?)\1\)(?:\?\.getAttribute\((['"])(.+?)\3\)|(.*))$"""
)


class ExpressionError(ValueError):
    pass


def parse_path(text: str) -> list[str | int]:
    """'a.b?.[0]['c-d']' to ['a', 'b', 0, 'c-d']. Anything else is rejected."""
    text = text.strip()
    keys: list[str | int] = []
    pos = 0
    while pos < len(text):
        match = _PATH_TOKEN.match(text, pos)
        if not match or match.end() == pos:
            raise ExpressionError(f"not a property read: {text!r}")
        name, single, double, index = match.groups()
        if name is not None:
            keys.append(name)
        elif index is not None:
            keys.append(int(index))
        else:
            keys.append(single if single is not None else double)
        pos = match.end()
    if keys and keys[0] == "window":
        keys = keys[1:]
    if not keys:
        raise ExpressionError(f"empty expression: {text!r}")
    return keys


def parse_part(text: str) -> dict:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return {"literal": text[1:-1]}
    selector = _SELECTOR.match(text)
    if selector:
        part = {"selector": selector.group(2)}
        if selector.group(4):
            part["attribute"] = selector.group(4)
        elif selector.group(5):
            part["path"] = parse_path(selector.group(5))
        return part
    return {"path": parse_path(text)}


def parse_expression(text: str) -> list[dict]:
    """Split on + outside quotes; each piece is a literal, a selector read or a path."""
    pieces, current, quote = [], "", None
    for char in text:
        if quote:
            current += char
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
            current += char
        elif char == "+":
            pieces.append(current)
            current = ""
        else:
            current += char
    pieces.append(current)
    return [parse_part(p) for p in pieces]


@dataclass
class Library:
    name: str
    npm: str | None
    version: list[str] = field(default_factory=list)
    parsed: list[list[dict]] = field(default_factory=list)
    detect: list[str | int] | None = None
    unless: list[list[str | int]] = field(default_factory=list)
    template: str | None = None
    strip: str | None = None
    eol: str | None = None
    verified: str | bool | None = None
    no_lookup: bool = False
    raw: dict = field(default_factory=dict)

    def to_page(self) -> dict:
        return {
            "name": self.name,
            "version": self.parsed,
            "sources": self.version,
            "detect": self.detect,
            "unless": self.unless,
        }

    def normalise(self, value: str) -> str:
        if self.strip:
            value = re.sub(self.strip, "", value)
        return self.template.format(value) if self.template else value


def load_libraries(text: str | None = None, include_verify_only: bool = False) -> list[Library]:
    data = yaml.safe_load(text if text is not None else datafiles.read_text("js_runtime.yaml"))
    libraries = []
    for entry in data.get("libraries", []):
        if entry.get("verify_only") and not include_verify_only:
            continue
        lib = Library(
            name=entry["name"],
            npm=entry.get("npm"),
            version=[str(v) for v in entry.get("version") or []],
            template=entry.get("template"),
            strip=entry.get("strip"),
            eol=entry.get("eol"),
            verified=entry.get("verified"),
            no_lookup=bool(entry.get("no_lookup")),
            raw=entry,
        )
        lib.parsed = [parse_expression(v) for v in lib.version]
        if entry.get("detect"):
            lib.detect = parse_path(str(entry["detect"]))
        lib.unless = [parse_path(str(u)) for u in entry.get("unless") or []]
        libraries.append(lib)
    return libraries


@lru_cache(maxsize=1)
def libraries() -> list[Library]:
    return load_libraries()


def validate(text: str) -> None:
    """Used by `update`: raises if the file would not load."""
    libs = load_libraries(text, include_verify_only=True)
    if not libs:
        raise ValueError("no libraries")


# Runs in the page through Playwright (not subject to the page's CSP). It only walks
# properties and reads attributes, then keeps values that look like versions.
EVALUATOR = r"""
(entries) => {
  const walk = (base, keys) => {
    let value = base;
    for (const key of keys) {
      if (value === undefined || value === null) return undefined;
      try { value = value[key]; } catch (e) { return undefined; }
    }
    return value;
  };
  const part = (p) => {
    if ('literal' in p) return p.literal;
    if ('selector' in p) {
      let el;
      try { el = document.querySelector(p.selector); } catch (e) { return undefined; }
      if (!el) return undefined;
      if (p.attribute) return el.getAttribute(p.attribute) ?? undefined;
      return walk(el, p.path || []);
    }
    return walk(window, p.path);
  };
  const out = {};
  for (const e of entries) {
    if ((e.unless || []).some((u) => walk(window, u) !== undefined)) continue;
    const present = e.detect ? walk(window, e.detect) !== undefined : false;
    let found = null;
    for (let i = 0; i < e.version.length; i++) {
      const values = e.version[i].map(part);
      if (values.some((v) => v === undefined || v === null || typeof v === 'object' || typeof v === 'function')) continue;
      let text = values.join('').trim();
      if (/^v\d/.test(text)) text = text.slice(1);
      if (/^\d+(\.\d+)*/.test(text)) { found = { version: text, expression: e.sources[i] }; break; }
    }
    if (found) out[e.name] = found;
    else if (present) out[e.name] = { version: null, expression: null };
  }
  return out;
}
"""

# Reads the properties webappanalyzer's `js` fingerprints look for.
JS_PROPERTIES = r"""
(chains) => {
  const out = {};
  for (const chain of chains) {
    let value = window;
    let ok = true;
    for (const key of chain.split('.')) {
      if (value === undefined || value === null) { ok = false; break; }
      try { value = value[key]; } catch (e) { ok = false; break; }
    }
    if (!ok || value === undefined) continue;
    const kind = typeof value;
    out[chain] = (kind === 'string' || kind === 'number' || kind === 'boolean') ? String(value) : '';
  }
  return out;
}
"""

# Reads the elements webappanalyzer's `dom` fingerprints look for.
DOM_QUERY = r"""
(queries) => {
  const out = {};
  for (const q of queries) {
    let el;
    try { el = document.querySelector(q.selector); } catch (e) { continue; }
    if (!el) continue;
    const item = { text: (el.textContent || '').slice(0, 2000), attributes: {}, properties: {} };
    for (const a of q.attributes || []) { const v = el.getAttribute(a); if (v !== null) item.attributes[a] = v; }
    for (const p of q.properties || []) {
      let v; try { v = el[p]; } catch (e) { v = undefined; }
      if (v !== undefined && v !== null) item.properties[p] = (typeof v === 'object' || typeof v === 'function') ? '' : String(v);
    }
    out[q.selector] = item;
  }
  return out;
}
"""

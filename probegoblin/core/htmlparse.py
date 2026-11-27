"""Small, forgiving HTML extraction using the standard library parser."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

SOURCE_MAP_RE = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*([^\s'\"*]+)")


@dataclass
class ScriptTag:
    src: str
    integrity: str | None = None
    crossorigin: str | None = None
    type: str | None = None


@dataclass
class Form:
    action: str | None
    method: str
    inputs: list[tuple[str, str]] = field(default_factory=list)  # (type, name)

    @property
    def has_password(self) -> bool:
        return any(kind == "password" for kind, _ in self.inputs)


@dataclass
class HtmlInfo:
    title: str = ""
    scripts: list[ScriptTag] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    links: list[dict[str, str]] = field(default_factory=list)
    metas: list[dict[str, str]] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    resources: list[tuple[str, str]] = field(default_factory=list)  # (kind, url)

    def meta_content(self, name: str) -> list[str]:
        name = name.lower()
        out = []
        for meta in self.metas:
            key = (meta.get("name") or meta.get("property") or "").lower()
            if key == name and "content" in meta:
                out.append(meta["content"])
        return out

    def http_equiv(self, name: str) -> list[str]:
        name = name.lower()
        return [
            m.get("content", "") for m in self.metas if (m.get("http-equiv") or "").lower() == name
        ]

    @property
    def icon_hrefs(self) -> list[str]:
        out = []
        for link in self.links:
            rels = link.get("rel", "").lower().split()
            if "icon" in rels and link.get("href"):
                out.append(link["href"])
        return out

    @property
    def modulepreloads(self) -> list[str]:
        return [
            link["href"]
            for link in self.links
            if "modulepreload" in link.get("rel", "").lower().split() and link.get("href")
        ]


ACTIVE = {"script", "iframe", "frame", "stylesheet", "object", "embed"}


def _resource_kind(tag: str, attrs: dict[str, str]) -> str | None:
    """Subresources that matter for mixed content."""
    if tag in ("script", "iframe", "frame", "embed") and attrs.get("src"):
        return tag
    if tag == "object" and attrs.get("data"):
        return "object"
    if tag == "link" and "stylesheet" in attrs.get("rel", "").lower().split():
        return "stylesheet"
    if tag in ("img", "audio", "video", "source", "track") and attrs.get("src"):
        return tag
    if tag == "form" and attrs.get("action"):
        return "form"
    return None


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.info = HtmlInfo()
        self._in_title = False
        self._in_script = False
        self._script_buf: list[str] = []
        self._form: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        info = self.info
        kind = _resource_kind(tag, a)
        if kind:
            ref = a.get("src") or a.get("href") or a.get("data") or a.get("action") or ""
            if ref:
                info.resources.append((kind, ref))
        if tag == "title":
            self._in_title = True
        elif tag == "script":
            if a.get("src"):
                info.scripts.append(
                    ScriptTag(
                        src=a["src"],
                        integrity=a.get("integrity") or None,
                        crossorigin=a.get("crossorigin"),
                        type=a.get("type"),
                    )
                )
                info.urls.append(a["src"])
            else:
                self._in_script = True
                self._script_buf = []
        elif tag == "link":
            info.links.append(a)
            if a.get("href"):
                info.urls.append(a["href"])
        elif tag == "meta":
            info.metas.append(a)
        elif tag == "form":
            self._form = Form(action=a.get("action"), method=(a.get("method") or "get").lower())
            info.forms.append(self._form)
            if a.get("action"):
                info.urls.append(a["action"])
        elif tag in ("input", "textarea", "select", "button") and self._form is not None:
            kind = a.get("type", "text" if tag == "input" else tag).lower()
            self._form.inputs.append((kind, a.get("name", "")))
        elif tag in ("a", "iframe", "img", "area") and (a.get("href") or a.get("src")):
            info.urls.append(a.get("href") or a.get("src"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._in_script:
            self._in_script = False
            text = "".join(self._script_buf)
            if text.strip():
                self.info.inline_scripts.append(text)
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.info.title:
            self.info.title = " ".join(data.split())
        if self._in_script:
            self._script_buf.append(data)


def parse_html(text: str) -> HtmlInfo:
    parser = _Parser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # malformed markup must never stop a scan
        pass
    info = parser.info
    for script in info.inline_scripts:
        info.source_maps.extend(SOURCE_MAP_RE.findall(script))
    return info


def source_maps_in(text: str) -> list[str]:
    return SOURCE_MAP_RE.findall(text[-4096:] if len(text) > 4096 else text)

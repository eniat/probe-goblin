"""Set-Cookie parsing and cookie purpose guessing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SESSION_NAMES = {
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "aspsessionid",
    "laravel_session",
    "connect.sid",
    "ci_session",
    "cfid",
    "cftoken",
    "sessionid",
    "session",
    "sid",
    "_session_id",
    "rack.session",
    "express:sess",
    "koa.sess",
    "frontend",
    "symfony",
    "moodlesession",
    "zm_session",
    "nsession",
    ".aspxauth",
    ".aspnetcore.session",
    ".aspnetcore.cookies",
}
SESSION_HINTS = re.compile(r"sess|^sid$|_sid$|auth|token$|^jwt|login|identity", re.I)
CSRF_HINTS = re.compile(r"csrf|xsrf|antiforgery|requestverificationtoken|^_token$", re.I)
ANALYTICS_HINTS = re.compile(
    r"^(_ga|_gid|_gat|_gcl_|_fbp|_fbc|_hj|_clck|_clsk|_uet|ajs_|mp_|amplitude|_pk_|_hs|hubspot|"
    r"__utm|_dc_gtm|__hstc|__hssc|__hssrc|_tt_|_ttp|_scid|_pin_|_rdt_|optimizely|_vwo|_lr_)",
    re.I,
)
PREFERENCE_HINTS = re.compile(
    r"lang|locale|language|theme|currency|consent|cookieyes|cookielaw|optanon|cookie_notice|"
    r"cookieconsent|gdpr|timezone|tz$|region|country|dismiss",
    re.I,
)
INFRA_HINTS = re.compile(
    r"^(awsalb|awsalbcors|awselb|bigipserver|arraffinity|arraffinitysamesite|__cf_bm|cf_clearance|"
    r"__cfruid|_cfuvid|incap_ses|visid_incap|nlbi_|ts0|akavpau|ak_bmsc|bm_sv|bm_sz|_abck|"
    r"sticky|route|serverid|lb)",
    re.I,
)

SESSION = "session"
CSRF = "csrf"
ANALYTICS = "analytics"
PREFERENCE = "preference"
INFRASTRUCTURE = "load balancer or CDN"
UNKNOWN = "unknown"


@dataclass
class SetCookie:
    name: str
    value: str
    attrs: dict[str, str] = field(default_factory=dict)  # lowercased keys, raw values
    raw: str = ""
    source_url: str = ""
    from_browser: bool = False

    def has(self, attr: str) -> bool:
        return attr in self.attrs

    @property
    def secure(self) -> bool:
        return "secure" in self.attrs

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attrs

    @property
    def samesite(self) -> str | None:
        value = self.attrs.get("samesite")
        return value.strip() if value is not None else None

    @property
    def domain(self) -> str | None:
        value = self.attrs.get("domain")
        return value.strip() if value else None

    @property
    def path(self) -> str | None:
        return self.attrs.get("path")

    @property
    def persistent(self) -> bool:
        return "expires" in self.attrs or "max-age" in self.attrs

    def signature(self) -> tuple:
        keys = ("secure", "httponly", "samesite", "domain", "path", "max-age")
        normal = tuple((k, (self.attrs.get(k) or "").lower()) for k in keys if k in self.attrs)
        return normal + (("persistent", self.persistent),)


def parse_set_cookie(header: str) -> SetCookie | None:
    parts = header.split(";")
    first = parts[0]
    if "=" not in first:
        return None
    name, value = first.split("=", 1)
    name = name.strip()
    if not name:
        return None
    cookie = SetCookie(name=name, value=value.strip().strip('"'), raw=header)
    for part in parts[1:]:
        if not part.strip():
            continue
        key, _, val = part.partition("=")
        key = key.strip().lower()
        if key and key not in cookie.attrs:
            cookie.attrs[key] = val.strip()
    return cookie


def purpose(name: str) -> str:
    lowered = name.lower()
    for prefix in ("__host-", "__secure-"):
        if lowered.startswith(prefix):
            lowered = lowered[len(prefix) :]
    if CSRF_HINTS.search(lowered):
        return CSRF
    if lowered in SESSION_NAMES:
        return SESSION
    if ANALYTICS_HINTS.search(lowered):
        return ANALYTICS
    if INFRA_HINTS.search(lowered):
        return INFRASTRUCTURE
    if PREFERENCE_HINTS.search(lowered):
        return PREFERENCE
    if SESSION_HINTS.search(lowered):
        return SESSION
    return UNKNOWN

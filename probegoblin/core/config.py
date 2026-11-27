"""Settings: code defaults, overridden by a TOML file, overridden by CLI options."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, Field

from probegoblin import __version__

USER_CONFIG = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "probegoblin"
USER_CONFIG_FILE = USER_CONFIG / "probegoblin.toml"

AUTH_PATHS = [
    "/login",
    "/signin",
    "/sign-in",
    "/account/login",
    "/user/login",
    "/auth/login",
    "/account",
    "/my-account",
    "/profile",
    "/register",
    "/signup",
    "/forgot-password",
    "/password/reset",
    "/reset-password",
]

API_PATHS = [
    "/api",
    "/api/v1",
    "/swagger",
    "/swagger-ui/",
    "/swagger-ui.html",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/swagger.json",
    "/graphql",
    "/graphiql",
]

DISCLOSURE_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/.DS_Store",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/web.config",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/backup.zip",
    "/site.zip",
]

# URLs matching these words are never requested, so a supplied session is not ended
# and nothing is removed by a GET that the application treats as an action.
UNSAFE_URL_WORDS = [
    "logout",
    "log-out",
    "log_out",
    "signout",
    "sign-out",
    "sign_out",
    "logoff",
    "delete",
    "remove",
    "destroy",
    "unsubscribe",
]


class ToolLimits(BaseModel):
    testssl: int = 900
    wafw00f: int = 120
    whatweb: int = 60


class Settings(BaseModel):
    rate: float = 3.0
    concurrency: int = 3
    max_requests: int = 300
    timeout: float = 10.0
    max_response_bytes: int = 2 * 1024 * 1024
    max_js_bytes: int = 5 * 1024 * 1024
    max_js_files: int = 30
    max_robots_urls: int = 20
    max_redirects: int = 5
    blocked_threshold: int = 5
    browser_page_limit: int = 8
    user_agent: str = f"ProbeGoblin/{__version__}"
    extra_headers: dict[str, str] = Field(default_factory=dict)
    auth_paths: list[str] = Field(default_factory=lambda: list(AUTH_PATHS))
    api_paths: list[str] = Field(default_factory=lambda: list(API_PATHS))
    disclosure_paths: list[str] = Field(default_factory=lambda: list(DISCLOSURE_PATHS))
    unsafe_url_words: list[str] = Field(default_factory=lambda: list(UNSAFE_URL_WORDS))
    tool_limits: ToolLimits = Field(default_factory=ToolLimits)

    # Runtime only, never read from a file.
    cookie: str | None = Field(default=None, exclude=True)
    headers: dict[str, str] = Field(default_factory=dict, exclude=True)
    pinned_ip: str | None = Field(default=None, exclude=True)
    assume_yes: bool = Field(default=False, exclude=True)
    verbose: bool = Field(default=False, exclude=True)

    @property
    def known_paths(self) -> list[str]:
        return [*self.auth_paths, *self.api_paths]

    def secret_values(self) -> list[str]:
        """Values that must never appear in output."""
        values = []
        if self.cookie:
            values.append(self.cookie)
            for part in self.cookie.split(";"):
                if "=" in part:
                    value = part.split("=", 1)[1].strip()
                    if len(value) >= 4:
                        values.append(value)
        for value in self.headers.values():
            if len(value) >= 4:
                values.append(value)
        return sorted(set(values), key=len, reverse=True)


def load_settings(path: Path | None = None) -> Settings:
    """Load defaults, then the user config file (or the one given) if it exists."""
    file = path or USER_CONFIG_FILE
    if path is not None and not path.is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    if file.is_file():
        with file.open("rb") as handle:
            data = tomllib.load(handle)
        return Settings.model_validate(data)
    return Settings()

"""Locate data files: the copy from `probegoblin update` if present, else the bundled one."""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path

USER_DATA = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "probegoblin"


def user_data() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "probegoblin"


def bundled(name: str) -> Path:
    return Path(str(resources.files("probegoblin.data").joinpath(name)))


def path(name: str) -> Path:
    """User copy (written only after validation by `update`), else the bundled copy."""
    user = user_data() / name
    if user.exists():
        return user
    return bundled(name)


def read_text(name: str) -> str:
    return path(name).read_text("utf-8")


def origin(name: str) -> str:
    return "updated" if (user_data() / name).exists() else "bundled"

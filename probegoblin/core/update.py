"""`probegoblin update`: refresh fingerprint data into ~/.local/share/probegoblin.

Every file is downloaded to a temporary location and validated before it replaces the old
copy. If anything fails, the previous copy (or the bundled one) stays in use."""

from __future__ import annotations

import json
import shutil
import tempfile
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from probegoblin import __version__
from probegoblin.core import datafiles

RAW = "https://raw.githubusercontent.com"
RETIRE_URL = f"{RAW}/RetireJS/retire.js/master/repository/jsrepository.json"
WAPPALYZER = f"{RAW}/enthec/webappanalyzer/main/src"
PROBEGOBLIN = f"{RAW}/eniat/probe-goblin/main/probegoblin/data"
LETTERS = ["_", *"abcdefghijklmnopqrstuvwxyz"]
OWN_FILES = [
    "js_runtime.yaml",
    "path_packs.toml",
    "favicons.toml",
    "csp_bypass.txt",
    "cdn_ranges.toml",
]


@dataclass
class UpdateResult:
    name: str
    ok: bool
    detail: str


def _validate_retire(text: str) -> None:
    from probegoblin.modules import _retire

    _retire.validate(text)


def _validate_technologies(text: str) -> None:
    data = json.loads(text)
    if not isinstance(data, dict) or not all(
        isinstance(v, dict) and "cats" in v for v in data.values()
    ):
        raise ValueError("not a webappanalyzer technologies file")


def _validate_categories(text: str) -> None:
    data = json.loads(text)
    if not isinstance(data, dict) or not all("name" in v for v in data.values()):
        raise ValueError("not a webappanalyzer categories file")


def _validate_toml(key: str) -> Callable[[str], None]:
    def check(text: str) -> None:
        data = tomllib.loads(text)
        if key not in data:
            raise ValueError(f"missing [{key}]")

    return check


def _validate_csp(text: str) -> None:
    entries = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    if not entries or not all(line.startswith("//") for line in entries):
        raise ValueError("not a CSP bypass list")


def _validate_runtime(text: str) -> None:
    from probegoblin.core import jsruntime

    jsruntime.validate(text)


VALIDATORS: dict[str, Callable[[str], None]] = {
    "js_runtime.yaml": _validate_runtime,
    "path_packs.toml": _validate_toml("pack"),
    "favicons.toml": _validate_toml("favicon"),
    "csp_bypass.txt": _validate_csp,
    "cdn_ranges.toml": _validate_toml("cdn"),
}


def _stamp(path: Path, source: str) -> None:
    now = datetime.now(UTC).strftime("%Y-%m-%d")
    path.write_text(f"{now} from {source} (probegoblin update)\n", "utf-8")


class Updater:
    def __init__(self, client: httpx.Client | None = None, root: Path | None = None) -> None:
        self.client = client or httpx.Client(
            timeout=60, headers={"User-Agent": f"ProbeGoblin/{__version__}"}
        )
        self.root = root or datafiles.user_data()

    def fetch(self, url: str) -> str:
        response = self.client.get(url)
        if response.status_code != 200:
            raise ValueError(f"HTTP {response.status_code}")
        return response.text

    def run(self) -> list[UpdateResult]:
        self.root.mkdir(parents=True, exist_ok=True)
        return [self.retire(), self.webappanalyzer(), *[self.own(name) for name in OWN_FILES]]

    def _replace_file(self, target: Path, text: str) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".new")
        tmp.write_text(text, "utf-8")
        tmp.replace(target)

    def retire(self) -> UpdateResult:
        name = "RetireJS repository"
        try:
            text = self.fetch(RETIRE_URL)
            _validate_retire(text)
        except (httpx.HTTPError, ValueError) as exc:
            return UpdateResult(name, False, f"kept the current copy ({exc})")
        self._replace_file(self.root / "retirejs" / "jsrepository.json", text)
        _stamp(self.root / "retirejs" / "RETRIEVED", "github.com/RetireJS/retire.js")
        return UpdateResult(name, True, f"{len(json.loads(text))} libraries")

    def webappanalyzer(self) -> UpdateResult:
        name = "webappanalyzer fingerprints"
        staging = Path(tempfile.mkdtemp(prefix="probegoblin-update-"))
        try:
            (staging / "technologies").mkdir()
            count = 0
            for letter in LETTERS:
                text = self.fetch(f"{WAPPALYZER}/technologies/{letter}.json")
                _validate_technologies(text)
                count += len(json.loads(text))
                (staging / "technologies" / f"{letter}.json").write_text(text, "utf-8")
            categories = self.fetch(f"{WAPPALYZER}/categories.json")
            _validate_categories(categories)
            (staging / "categories.json").write_text(categories, "utf-8")
            _stamp(staging / "RETRIEVED", "github.com/enthec/webappanalyzer")
        except (httpx.HTTPError, ValueError) as exc:
            shutil.rmtree(staging, ignore_errors=True)
            return UpdateResult(name, False, f"kept the current copy ({exc})")
        target = self.root / "webappanalyzer"
        old = target.with_name("webappanalyzer.old")
        shutil.rmtree(old, ignore_errors=True)
        if target.exists():
            target.rename(old)
        shutil.move(str(staging), str(target))
        shutil.rmtree(old, ignore_errors=True)
        return UpdateResult(name, True, f"{count} technologies")

    def own(self, filename: str) -> UpdateResult:
        try:
            text = self.fetch(f"{PROBEGOBLIN}/{filename}")
            VALIDATORS[filename](text)
        except (httpx.HTTPError, ValueError, tomllib.TOMLDecodeError) as exc:
            return UpdateResult(filename, False, f"kept the current copy ({exc})")
        except Exception as exc:  # a broken YAML file must never replace a good one
            return UpdateResult(filename, False, f"kept the current copy ({type(exc).__name__})")
        self._replace_file(self.root / filename, text)
        return UpdateResult(filename, True, "updated")

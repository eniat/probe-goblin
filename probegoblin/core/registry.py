"""Discovers Goblins in probegoblin/modules. Drop a file in, no engine edits needed."""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING, ClassVar

from probegoblin.core.models import Finding, ModuleResult, Status

if TYPE_CHECKING:
    from probegoblin.core.config import Settings
    from probegoblin.core.context import TargetContext

STAGE_HTTP = "http"
STAGE_EXTERNAL = "external"


class Goblin:
    """Base class for a module. Subclass it in a file under probegoblin/modules."""

    name: ClassVar[str] = ""
    flag: ClassVar[str] = ""
    prefix: ClassVar[str] = ""
    order: ClassVar[int] = 1000
    description: ClassVar[str] = ""
    stage: ClassVar[str] = STAGE_HTTP
    needs_pages: ClassVar[bool] = True
    uses_browser: ClassVar[bool] = False

    def unavailable_reason(self) -> str | None:
        """Why the module cannot run at all on this machine, or None."""
        return None

    def estimate_requests(self, settings: Settings) -> int:
        return 0

    async def run(self, ctx: TargetContext) -> ModuleResult:
        raise NotImplementedError

    def result(self) -> ModuleResult:
        return ModuleResult(module=self.name)

    def finding(self, **kwargs) -> Finding:
        return Finding(module=self.name, **kwargs)

    def not_assessed(self, url: str, title: str, reason: str) -> Finding:
        return Finding(
            module=self.name,
            title=title,
            status=Status.NOT_ASSESSED,
            affected_url=url,
            observed=f"Not assessed: {reason}",
            why_it_matters="This check did not run, so the result is unknown.",
        )


def discover() -> list[Goblin]:
    from probegoblin import modules

    found: list[Goblin] = []
    for info in pkgutil.iter_modules(modules.__path__):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"{modules.__name__}.{info.name}")
        for value in vars(module).values():
            if (
                isinstance(value, type)
                and issubclass(value, Goblin)
                and value is not Goblin
                and value.__module__ == module.__name__
                and value.name
            ):
                found.append(value())
    stages = {STAGE_HTTP: 0, STAGE_EXTERNAL: 1}
    return sorted(found, key=lambda g: (stages.get(g.stage, 2), g.order, g.name))


ID_ORDER = [Status.ISSUE, Status.MANUAL_CHECK, Status.OBSERVATION, Status.NOT_ASSESSED, Status.OK]


def assign_ids(goblin: Goblin, result: ModuleResult) -> None:
    """Number findings with problems first, so IDs read in the order they are shown."""
    result.findings.sort(key=lambda f: ID_ORDER.index(f.status))
    for number, finding in enumerate(result.findings, start=1):
        finding.finding_id = f"{goblin.prefix}-{number:03d}"

"""Runs discovery and the selected modules for each target, in order."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import IO, Any

from probegoblin.core import browser as browser_stage
from probegoblin.core.config import Settings
from probegoblin.core.context import TargetContext
from probegoblin.core.discovery import Discovery, PageStore
from probegoblin.core.http_client import (
    RequestCapReachedError,
    SafeClient,
    Scope,
    TargetBlockedError,
)
from probegoblin.core.models import ModuleResult, TargetResult
from probegoblin.core.preflight import TargetPlan
from probegoblin.core.registry import Goblin, assign_ids

ProgressFn = Callable[[str], None]
BlockedFn = Callable[[str], Awaitable[str]]


def browser_urls(store: PageStore) -> list[str]:
    """Landing page plus up to three login, account or password reset pages that returned 200."""
    landing = store.landing
    urls = [landing.final_url or landing.url]
    for page in store.tagged("login", "account", "password_reset"):
        url = page.final_url or page.url
        if page.status == 200 and url not in urls:
            urls.append(url)
    return urls[: 1 + browser_stage.MAX_AUTH_PAGES]


class ScanInterruptedError(Exception):
    """Raised inside the engine when Ctrl+C was pressed."""


class Engine:
    def __init__(
        self,
        settings: Settings,
        goblins: list[Goblin],
        progress: ProgressFn | None = None,
        on_blocked: BlockedFn | None = None,
        request_log: IO[str] | None = None,
    ) -> None:
        self.settings = settings
        self.goblins = goblins
        self.progress = progress or (lambda _label: None)
        self.on_blocked = on_blocked
        self.request_log = request_log
        self.interrupted = False
        self._current: asyncio.Task | None = None

    def interrupt(self) -> None:
        self.interrupted = True
        if self._current is not None and not self._current.done():
            self._current.cancel()

    async def _step(self, coro: Awaitable[Any]) -> Any:
        if self.interrupted:
            if asyncio.iscoroutine(coro):
                coro.close()
            raise ScanInterruptedError
        self._current = asyncio.ensure_future(coro)
        try:
            return await self._current
        except asyncio.CancelledError:
            if self.interrupted:
                raise ScanInterruptedError from None
            raise
        finally:
            self._current = None

    async def scan(self, plans: list[TargetPlan]) -> list[TargetResult]:
        results = []
        for plan in plans:
            results.append(await self.scan_target(plan))
        return results

    async def scan_target(self, plan: TargetPlan) -> TargetResult:
        result = TargetResult(
            target=plan.url or plan.raw,
            host=plan.host,
            ips=plan.ips,
            cdn=plan.cdn,
            pinned_ip=plan.pinned_ip,
        )
        if plan.error:
            result.skipped_reason = plan.error
            return result
        started = time.monotonic()
        scope = Scope.from_url(plan.url, plan.ips)
        client = SafeClient(
            self.settings, scope, request_log=self.request_log, on_blocked=self.on_blocked
        )
        store = PageStore(target=plan.url)
        ctx = TargetContext(
            target=plan.url,
            host=plan.host,
            scheme=plan.scheme,
            port=plan.port,
            settings=self.settings,
            client=client,
            store=store,
            ips=plan.ips,
            cdn=plan.cdn,
        )
        try:
            try:
                self.progress(f"{plan.host}: building page store")
                ctx.store = await self._step(Discovery(client, self.settings, plan.url).run())
            except ScanInterruptedError:
                result.interrupted = True
            if not result.interrupted:
                await self._browser(ctx, result)
            for goblin in self.goblins:
                module_result = await self._run_goblin(goblin, ctx, result)
                assign_ids(goblin, module_result)
                ctx.results[goblin.name] = module_result
                result.modules.append(module_result)
        finally:
            await client.aclose()
        result.requests_sent = client.sent
        result.blocked = client.blocked_responses
        result.skipped_urls = list(ctx.store.skipped)
        result.tech_summary = [t.label for t in ctx.tech]
        result.favicon_hash = ctx.summary.get("favicon_hash")
        result.waf_summary = ctx.summary.get("waf")
        result.tls_summary = ctx.summary.get("tls")
        result.duration = time.monotonic() - started
        return result

    async def _browser(self, ctx: TargetContext, result: TargetResult) -> None:
        names = {g.name for g in self.goblins}
        if not any(g.uses_browser for g in self.goblins):
            return
        landing = ctx.store.landing
        if landing is None or landing.status is None:
            ctx.browser_reason = "landing page could not be retrieved"
            return
        reason = browser_stage.unavailable_reason()
        if reason:
            ctx.browser_reason = reason
            return
        chains, queries = [], []
        if "TechnologyGoblin" in names:
            from probegoblin.modules import _fingerprints

            chains, queries = _fingerprints.browser_queries()
        stage = browser_stage.BrowserStage(
            ctx.target,
            self.settings,
            js_chains=chains,
            dom_queries=queries,
            frame_test="ClickjackGoblin" in names,
        )
        self.progress(f"{ctx.host}: browser stage")
        try:
            ctx.browser = await self._step(stage.run(browser_urls(ctx.store)))
            result.pages_browsed = ctx.browser.loads
        except ScanInterruptedError:
            result.interrupted = True
        except Exception as exc:  # a browser crash must not lose the rest of the scan
            ctx.browser = None
            first = str(exc).splitlines()[0][:160] if str(exc) else ""
            ctx.browser_reason = f"browser stage failed: {type(exc).__name__} {first}".strip()

    async def _run_goblin(
        self, goblin: Goblin, ctx: TargetContext, result: TargetResult
    ) -> ModuleResult:
        empty = ModuleResult(module=goblin.name)
        if self.interrupted or result.interrupted:
            result.interrupted = True
            empty.not_assessed_reason = "interrupted"
            return empty
        reason = goblin.unavailable_reason()
        if reason:
            empty.not_assessed_reason = reason
            return empty
        landing = ctx.store.landing
        if goblin.needs_pages and (landing is None or landing.status is None):
            why = landing.error if landing and landing.error else "no response"
            empty.not_assessed_reason = f"landing page could not be retrieved ({why})"
            return empty
        self.progress(f"{ctx.host}: {goblin.name}")
        started = time.monotonic()
        try:
            module_result = await self._step(goblin.run(ctx))
        except ScanInterruptedError:
            result.interrupted = True
            empty.not_assessed_reason = "interrupted"
            return empty
        except RequestCapReachedError:
            empty.not_assessed_reason = "request cap reached"
            return empty
        except TargetBlockedError:
            empty.not_assessed_reason = "stopped because the target kept blocking requests"
            return empty
        except Exception as exc:  # a module bug must not lose the rest of the scan
            empty.not_assessed_reason = f"module error: {type(exc).__name__}: {exc}"
            return empty
        module_result.duration = time.monotonic() - started
        return module_result

"""Runs external tools one at a time, with a hard time limit and clean shutdown."""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import signal
from dataclasses import dataclass

TOOL_NAMES: dict[str, tuple[str, ...]] = {
    "testssl": ("testssl", "testssl.sh"),
    "wafw00f": ("wafw00f",),
    "whatweb": ("whatweb",),
}

INSTALL_HINTS: dict[str, str] = {
    "testssl": "sudo apt install testssl.sh",
    "wafw00f": "sudo apt install wafw00f",
    "whatweb": "sudo apt install whatweb",
    "chromium": "probegoblin setup",
}

_locks: dict[asyncio.AbstractEventLoop, asyncio.Lock] = {}


def _lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    if loop not in _locks:
        _locks.clear()
        _locks[loop] = asyncio.Lock()
    return _locks[loop]


@dataclass
class ToolResult:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


def find_tool(tool: str) -> str | None:
    for name in TOOL_NAMES.get(tool, (tool,)):
        path = shutil.which(name)
        if path:
            return path
    return None


def _kill_group(proc: asyncio.subprocess.Process, sig: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, sig)


async def _stop(proc: asyncio.subprocess.Process) -> None:
    _kill_group(proc, signal.SIGTERM)
    try:
        await asyncio.wait_for(proc.wait(), 3)
    except TimeoutError:
        _kill_group(proc, signal.SIGKILL)
        await proc.wait()


async def run_tool(argv: list[str], timeout: float) -> ToolResult:
    """Run a tool in its own process group. On timeout or Ctrl+C the whole group is stopped."""
    async with _lock():
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except TimeoutError:
            await _stop(proc)
            return ToolResult(None, "", "", timed_out=True)
        except asyncio.CancelledError:
            await _stop(proc)
            raise
        return ToolResult(
            proc.returncode,
            out.decode("utf-8", errors="replace"),
            err.decode("utf-8", errors="replace"),
        )


async def tool_version(tool: str, args: tuple[str, ...] = ("--version",)) -> str | None:
    path = find_tool(tool)
    if path is None:
        return None
    try:
        result = await run_tool([path, *args], 15)
    except OSError:
        return None
    text = (result.stdout + "\n" + result.stderr).strip()
    return text or None

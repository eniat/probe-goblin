"""Checks every js_runtime.yaml expression against the real npm package in Chromium.

Run by hand (needs network and Chromium), not by pytest:

    python tests/verify_js_runtime.py [--write]

For each entry with a `test` file it downloads the package from the npm registry, loads the
file (after any `requires`) into a blank page and runs the same evaluator JSGoblin uses. With
--write it records the result in the `verified` field of probegoblin/data/js_runtime.yaml:
the npm version on success, false on failure.
"""

from __future__ import annotations

import asyncio
import io
import json
import re
import sys
import tarfile
import urllib.request
from pathlib import Path
from urllib.parse import quote

from playwright.async_api import async_playwright

from probegoblin.core import browser, jsruntime

ROOT = Path(__file__).resolve().parent.parent
YAML = ROOT / "probegoblin" / "data" / "js_runtime.yaml"
CACHE = Path.home() / ".cache" / "probegoblin" / "verify"


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed registry URL
        return response.read()


def package_file(npm: str, version: str, path: str) -> tuple[str, str]:
    """(resolved version, file text) from the npm tarball."""
    CACHE.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(fetch(f"https://registry.npmjs.org/{quote(npm, safe='@')}/{version}"))
    resolved = manifest["version"]
    tarball = CACHE / f"{npm.replace('/', '_')}-{resolved}.tgz"
    if not tarball.exists():
        tarball.write_bytes(fetch(manifest["dist"]["tarball"]))
    with tarfile.open(fileobj=io.BytesIO(tarball.read_bytes())) as archive:
        member = archive.extractfile(f"package/{path}")
        if member is None:
            raise FileNotFoundError(path)
        return resolved, member.read().decode("utf-8", "replace")


async def check(context, entry: dict, by_name: dict[str, dict]) -> tuple[str, str | None, str]:
    npm = entry.get("npm_test") or entry["npm"]
    want = entry.get("test_version", "latest")
    resolved, code = package_file(npm, want, entry["test"])
    page = await context.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda exc: errors.append(str(exc)[:120]))
    try:
        await page.goto("about:blank")
        for spec in entry.get("requires", []):
            name, _, pin = spec.partition("@")
            dep = by_name[name]
            _, dep_code = package_file(
                dep.get("npm_test") or dep["npm"],
                pin or dep.get("test_version", "latest"),
                dep["test"],
            )
            await page.add_script_tag(content=dep_code)
        await page.add_script_tag(content=code)
        lib = [
            lib
            for lib in jsruntime.load_libraries(include_verify_only=True)
            if lib.name == entry["name"]
        ][0]
        found = (await page.evaluate(jsruntime.EVALUATOR, [lib.to_page()])).get(entry["name"])
    finally:
        await page.close()
    if not lib.version:
        return resolved, resolved if found else None, "presence only"
    got = lib.normalise(found["version"]) if found and found.get("version") else None
    if got is None and found is not None:
        return resolved, resolved, "present; no version exposed"
    note = "; ".join(errors[:1])
    return resolved, got, note


async def main(write: bool) -> int:
    data_text = YAML.read_text("utf-8")
    import yaml

    entries = yaml.safe_load(data_text)["libraries"]
    by_name = {e["name"]: e for e in entries}
    results: dict[str, str | bool] = {}
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path=browser.chromium_path())
        context = await b.new_context()
        for entry in entries:
            if not entry.get("test"):
                continue
            try:
                resolved, got, note = await check(context, entry, by_name)
            except Exception as exc:  # report and carry on
                print(f"ERROR {entry['name']}: {type(exc).__name__}: {str(exc)[:100]}")
                results[entry["name"]] = False
                continue
            ok = got is not None and got == resolved
            lagging = got is not None and not ok and got.split(".")[:2] == resolved.split(".")[:2]
            if lagging:
                results[entry["name"]] = f"{resolved} (reports {got})"
            else:
                results[entry["name"]] = resolved if ok else False
            status = "ok  " if ok else ("lag " if lagging else "FAIL")
            print(f"{status} {entry['name']:<28} npm {resolved:<14} got {got} {note}")
        await b.close()
    passed = sum(1 for v in results.values() if v)
    print(f"\n{passed} of {len(results)} verified")
    if write:
        lines = data_text.splitlines()
        for index, line in enumerate(lines):
            match = re.match(r"- \{name: ([^,]+),", line)
            if not match or match.group(1) not in results:
                continue
            value = results[match.group(1)]
            line = re.sub(r", verified: [^,}]+", "", line)
            stamp = f"'{value}'" if value else "false"
            lines[index] = line[:-1] + f", verified: {stamp}}}"
        YAML.write_text("\n".join(lines) + "\n", "utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--write" in sys.argv)))

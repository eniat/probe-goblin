"""Terminal output with rich. The same output, ANSI stripped, is what --save writes."""

from __future__ import annotations

from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table as RichTable
from rich.text import Text

from probegoblin import TAGLINE, __version__
from probegoblin.core.models import Finding, ModuleResult, Status, Table, TargetResult
from probegoblin.core.preflight import TargetPlan
from probegoblin.core.registry import Goblin
from probegoblin.output import art

TITLE_SHADES = [
    "#b6f07a",
    "#9be564",
    "#86d856",
    "#6fc947",
    "#5ab83a",
    "#47a52f",
    "#389326",
    "#2c821e",
]
GOBLIN_SHADES = (
    ["#a8ec6c"] * 3 + ["#93e05c"] * 4 + ["#7fd24f"] * 5 + ["#6cc544"] * 5 + ["#5ab83a"] * 5
)
GOBLIN_SHADES += ["#4aa82f"] * (len(art.GOBLIN) - len(GOBLIN_SHADES))
STAFF = "#c8964a"

STATUS_STYLE = {
    Status.ISSUE: ("ISSUE", "bold white on red3"),
    Status.MANUAL_CHECK: ("MANUAL CHECK", "bold black on gold1"),
    Status.OBSERVATION: ("OBSERVATION", "bold white on dodger_blue3"),
    Status.OK: ("OK", "bold white on green4"),
    Status.NOT_ASSESSED: ("NOT ASSESSED", "bold white on grey42"),
}
ORDER = [Status.ISSUE, Status.MANUAL_CHECK, Status.OBSERVATION, Status.NOT_ASSESSED, Status.OK]
PLURAL = {
    Status.ISSUE: ("issue", "issues"),
    Status.MANUAL_CHECK: ("manual check", "manual checks"),
    Status.OBSERVATION: ("observation", "observations"),
    Status.OK: ("ok", "ok"),
    Status.NOT_ASSESSED: ("not assessed", "not assessed"),
}
COUNT_STYLE = {
    Status.ISSUE: "bold red",
    Status.MANUAL_CHECK: "bold gold1",
    Status.OBSERVATION: "bold dodger_blue1",
    Status.OK: "bold green",
    Status.NOT_ASSESSED: "grey50",
}


def counts_text(counts: dict[Status, int], include_zero: bool = False) -> Text:
    text = Text()
    parts = [
        (status, counts.get(status, 0)) for status in ORDER if include_zero or counts.get(status, 0)
    ]
    for index, (status, number) in enumerate(parts):
        if index:
            text.append(" | ", style="grey50")
        word = PLURAL[status][0 if number == 1 else 1]
        text.append(f"{number} {word}", style=COUNT_STYLE[status] if number else "grey50")
    return text


class Renderer:
    def __init__(self, console: Console, verbose: bool = False, secrets: list[str] | None = None):
        self.console = console
        self.verbose = verbose
        self.secrets = [s for s in (secrets or []) if s]

    def mask(self, value: str | None) -> str:
        text = value or ""
        for secret in self.secrets:
            text = text.replace(secret, "<masked>")
        return text

    # Banner and pre-flight

    @staticmethod
    def _goblin_row(row: int) -> Text:
        line = Text()
        for col, char in enumerate(art.GOBLIN[row]):
            colour = STAFF if art.is_staff(row, col) else GOBLIN_SHADES[row]
            line.append(char, style=colour)
        line.append(" " * (art.GOBLIN_WIDTH - len(art.GOBLIN[row])))
        return line

    def banner(self) -> None:
        """Goblin poking the title with its staff. Feet sit on the title's bottom line.

        Wide terminals get the title on one line, narrower ones "Probe" over "Goblin",
        then the goblin alone, then just the tagline."""
        tag = Text()
        tag.append(f"ProbeGoblin {__version__}", style="bold green3")
        tag.append(" | ", style="grey50")
        tag.append(TAGLINE, style="italic grey70")
        width = self.console.width
        wide = art.GOBLIN_WIDTH + max(len(line) for line in art.TITLE_WIDE)
        stacked_title = art.TITLE_PROBE + art.TITLE_GOBLIN
        stacked = art.GOBLIN_WIDTH + max(len(line) for line in stacked_title)
        if width >= wide:
            title = art.TITLE_WIDE
        elif width >= stacked:
            title = stacked_title
        else:
            title = []
        if width >= art.GOBLIN_WIDTH:
            first = len(art.GOBLIN) - len(title)
            for row in range(len(art.GOBLIN)):
                line = self._goblin_row(row)
                index = row - first
                if 0 <= index < len(title):
                    shade = TITLE_SHADES[index % len(TITLE_SHADES)]
                    line.append(title[index], style=f"bold {shade}")
                self.console.print(line, no_wrap=True, crop=True)
            self.console.print()
            pad = " " * art.GOBLIN_WIDTH if title else ""
            self.console.print(Text.assemble(pad, tag), no_wrap=True, crop=True)
        else:
            self.console.print(tag)
        self.console.print()

    def preflight(
        self,
        plans: list[TargetPlan],
        run: list[Goblin],
        skipped: list[tuple[Goblin, str]],
        requests: int,
        cap: int,
        browser_loads: int,
        browser_note: str | None,
    ) -> None:
        grid = RichTable.grid(padding=(0, 2))
        grid.add_column(style="bold green3", no_wrap=True)
        grid.add_column()
        for plan in plans:
            if plan.error:
                grid.add_row(
                    "Target", Text(f"{plan.raw}  ", style="bold") + Text(plan.error, "red")
                )
                continue
            grid.add_row("Target", Text(plan.url, style="bold"))
            ips = ", ".join(plan.ips) + (f" ({plan.cdn})" if plan.cdn else "")
            grid.add_row("Resolved" if not plan.pinned_ip else "Pinned", ips)
            if plan.note:
                grid.add_row("", Text(plan.note, style="gold1"))
        grid.add_row("Modules", ", ".join(g.name for g in run) or "none")
        for goblin, reason in skipped:
            grid.add_row("Skipped", Text(f"{goblin.name}: {reason}", style="grey62"))
        grid.add_row(
            "Requests", f"up to {min(requests, cap)} Python requests per target (cap {cap})"
        )
        if browser_note == "up to":
            loads = f"up to {browser_loads} page loads per target"
        else:
            loads = f"none ({browser_note})" if browser_note else "none"
        grid.add_row("Browser", loads)
        self.console.print(
            Panel(grid, title="[bold]Pre-flight[/]", border_style="green4", expand=False)
        )

    # Results

    def target(self, result: TargetResult) -> None:
        self.console.print()
        if result.skipped_reason:
            self.console.print(
                Panel(
                    Text(f"{result.target}\n{result.skipped_reason}"),
                    title="[bold]Skipped[/]",
                    border_style="red3",
                )
            )
            return
        self.console.print(self._summary_panel(result))
        for module in result.modules:
            self._module(module)
        self._footer(result)

    def _summary_panel(self, result: TargetResult) -> Panel:
        grid = RichTable.grid(padding=(0, 2))
        grid.add_column(style="bold green3", no_wrap=True)
        grid.add_column()
        grid.add_row("Target", Text(result.target, style="bold"))
        ips = ", ".join(result.ips) + (f" ({result.cdn})" if result.cdn else "")
        grid.add_row("Pinned" if result.pinned_ip else "Resolved", ips or "-")
        ran = {m.module for m in result.modules if not m.not_assessed_reason}
        if "TechnologyGoblin" in ran:
            tech = ", ".join(result.tech_summary[:8]) or "nothing identified"
            if len(result.tech_summary) > 8:
                tech += f" (+{len(result.tech_summary) - 8} more)"
            if result.favicon_hash is not None:
                tech += f" | favicon mmh3 {result.favicon_hash}"
            grid.add_row("Tech", self.mask(tech))
        else:
            grid.add_row("Tech", Text("not assessed in this run", "grey50"))
        grid.add_row("WAF", result.waf_summary or Text("not assessed in this run", "grey50"))
        grid.add_row("TLS", result.tls_summary or Text("not assessed in this run", "grey50"))
        minutes, seconds = divmod(int(result.duration), 60)
        grid.add_row(
            "Requests",
            f"{result.requests_sent} sent | {result.pages_browsed} pages browsed | "
            f"{result.blocked} blocked | {minutes}m {seconds:02d}s",
        )
        counts = self._counts(result.modules)
        grid.add_row("Results", counts_text(counts, include_zero=True))
        title = f"[bold]{result.host}[/]"
        if result.interrupted:
            title += " [bold red](interrupted)[/]"
        return Panel(grid, title=title, border_style="green4")

    @staticmethod
    def _counts(modules: list[ModuleResult]) -> dict[Status, int]:
        counts: dict[Status, int] = {}
        for module in modules:
            for finding in module.findings:
                counts[finding.status] = counts.get(finding.status, 0) + 1
            if module.not_assessed_reason and not module.findings:
                counts[Status.NOT_ASSESSED] = counts.get(Status.NOT_ASSESSED, 0) + 1
        return counts

    def _module(self, module: ModuleResult) -> None:
        counts = self._counts([module])
        header = Text(module.module, style="bold green3")
        header.append("   ")
        header.append_text(counts_text(counts))
        self.console.print()
        self.console.print(Rule(header, align="left", style="green4"))
        if module.not_assessed_reason:
            self.console.print(
                Padding(
                    Text(f"Not assessed: {self.mask(module.not_assessed_reason)}", "grey62"),
                    (0, 0, 0, 2),
                )
            )
        for table in module.tables:
            self._table(table)
        ordered = sorted(module.findings, key=lambda f: ORDER.index(f.status))
        for finding in ordered:
            if finding.status == Status.OK and not self.verbose:
                continue
            self._finding(finding)
        oks = counts.get(Status.OK, 0)
        if oks and not self.verbose:
            self.console.print(
                Padding(Text(f"{oks} ok (use --verbose to list)", "green"), (1, 0, 0, 2))
            )

    def _table(self, table: Table) -> None:
        rich_table = RichTable(
            title=table.title,
            title_style="bold",
            title_justify="left",
            header_style="bold green3",
            border_style="grey42",
            show_lines=False,
        )
        for column in table.columns:
            rich_table.add_column(column, overflow="fold")
        for row in table.rows:
            rich_table.add_row(*(self.mask(cell) for cell in row))
        self.console.print(Padding(rich_table, (1, 0, 0, 2)))

    def _finding(self, finding: Finding) -> None:
        label, style = STATUS_STYLE[finding.status]
        head = Text()
        head.append(f" {label} ", style=style)
        if finding.finding_id:
            head.append(f"  {finding.finding_id}", style="bold")
        head.append(f"  {self.mask(finding.title)}", style="bold")
        grid = RichTable.grid(padding=(0, 2))
        grid.add_column(style="grey62", no_wrap=True, min_width=10)
        grid.add_column(overflow="fold")
        grid.add_row("URL", self.mask(finding.affected_url))
        if finding.observed:
            grid.add_row("Observed", self.mask(finding.observed))
        if finding.expected:
            grid.add_row("Expected", self.mask(finding.expected))
        if finding.status != Status.OK:
            grid.add_row("Why", self.mask(finding.why_it_matters))
        if finding.remediation:
            grid.add_row("Fix", self.mask(finding.remediation))
        for index, command in enumerate(finding.reproduce):
            grid.add_row("Reproduce" if index == 0 else "", Text(self.mask(command), style="cyan"))
        for index, step in enumerate(finding.manual_steps):
            grid.add_row("Manual" if index == 0 else "", f"{index + 1}. {self.mask(step)}")
        for index, ref in enumerate(finding.references):
            grid.add_row("Ref" if index == 0 else "", Text(ref, style="grey62"))
        self.console.print()
        self.console.print(Padding(head, (0, 0, 0, 2)))
        self.console.print(Padding(grid, (0, 0, 0, 4)))

    def _footer(self, result: TargetResult) -> None:
        self.console.print()
        counts = self._counts(result.modules)
        summary = Text("Summary    ", style="bold green3")
        summary.append_text(counts_text(counts, include_zero=True))
        self.console.print(summary)
        missing: list[tuple[str, str]] = []
        for module in result.modules:
            if module.not_assessed_reason:
                missing.append((module.module, module.not_assessed_reason))
            for finding in module.findings:
                if finding.status == Status.NOT_ASSESSED:
                    reason = (finding.observed or "").removeprefix("Not assessed: ")
                    missing.append((module.module, f"{finding.title}: {reason}"))
        if missing:
            self.console.print(Text("Not assessed", style="bold grey70"))
            width = max(len(name) for name, _ in missing)
            for name, reason in missing:
                line = Text(f"  {name.ljust(width)}   ", style="grey70")
                line.append(self.mask(reason), style="grey62")
                self.console.print(line)
        if result.skipped_urls:
            self.console.print(Text("Not requested (look like actions such as logout)", "bold"))
            for url in result.skipped_urls:
                self.console.print(Text(f"  {self.mask(url)}", style="grey62"))

    def sign_off(self, results: list[TargetResult]) -> None:
        counts: dict[Status, int] = {}
        for result in results:
            for status, number in self._counts(result.modules).items():
                counts[status] = counts.get(status, 0) + number
        scanned = sum(1 for r in results if not r.skipped_reason)
        interrupted = any(r.interrupted for r in results)
        lines = [
            Text(f"{scanned} target{'s' if scanned != 1 else ''} poked", style="bold green3"),
            counts_text({k: v for k, v in counts.items() if k != Status.OK}, include_zero=False)
            or Text("nothing to report", style="green"),
            Text(
                (
                    "Interrupted: results above are partial."
                    if interrupted
                    else "Evidence gathering is over to you."
                ),
                style="bold red" if interrupted else "italic grey70",
            ),
        ]
        self.console.print()
        for line in lines:
            self.console.print(line)

    def combined(self, results: list[TargetResult]) -> None:
        if len(results) < 2:
            return
        table = RichTable(
            title="All targets",
            title_style="bold green3",
            title_justify="left",
            header_style="bold green3",
            border_style="grey42",
        )
        for column in ("Target", "Issues", "Manual checks", "Observations", "Not assessed", "Sent"):
            table.add_column(column)
        for result in results:
            if result.skipped_reason:
                table.add_row(result.target, "-", "-", "-", "-", Text("skipped", "red"))
                continue
            counts = self._counts(result.modules)
            table.add_row(
                result.target,
                str(counts.get(Status.ISSUE, 0)),
                str(counts.get(Status.MANUAL_CHECK, 0)),
                str(counts.get(Status.OBSERVATION, 0)),
                str(counts.get(Status.NOT_ASSESSED, 0)),
                str(result.requests_sent),
            )
        self.console.print()
        self.console.print(table)

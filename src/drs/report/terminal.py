from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from drs.models import SEVERITY_RANK, Finding, Report, iter_findings

_VERDICT = {
    "ready": "green",
    "not_ready": "red",
    "partial": "yellow",
}
_SEVERITY = {
    "blocker": "red",
    "high": "dark_orange3",
    "medium": "yellow3",
    "low": "cyan",
    "info": "dim",
}


def render_terminal(report: Report, console: Console | None = None) -> None:
    console = console or Console()
    header = Text()
    header.append(report.target_name, style="bold")
    header.append(f"  {report.environment}  ")
    header.append(report.verdict.value.replace("_", " "), style=f"bold {_VERDICT[report.verdict.value]}")
    console.print(header)
    console.print(Text(report.reason))
    console.print()

    scores = Table(box=None, show_header=True, header_style="bold", pad_edge=False)
    scores.add_column("category")
    scores.add_column("score", justify="right")
    scores.add_column("")
    for score in report.scores:
        label = "n/a" if score.score is None else str(score.score)
        bar = "" if score.score is None else _bar(score.score)
        scores.add_row(Text(score.category.value), Text(label), Text(bar))
    console.print(scores)
    console.print()

    checks = Table(box=None, show_header=True, header_style="bold", pad_edge=False)
    checks.add_column("check")
    checks.add_column("status")
    checks.add_column("ms", justify="right")
    checks.add_column("summary")
    for result in report.checks:
        checks.add_row(
            Text(result.check_id),
            Text(result.status.value),
            Text(str(result.duration_ms)),
            Text(result.summary),
        )
    console.print(checks)

    findings = sorted(iter_findings(report), key=lambda item: (SEVERITY_RANK[item.severity], item.check_id))
    if not findings:
        console.print()
        console.print("No findings.")
        return
    console.print()
    for finding in findings:
        console.print(_finding_line(finding))
        console.print(Text("  " + finding.summary))
        console.print(Text("  " + finding.remediation))
        console.print()


def _finding_line(finding: Finding) -> Text:
    line = Text()
    line.append(f"{finding.severity.value:<8}", style=_SEVERITY[finding.severity.value])
    line.append(f" {finding.check_id}  {finding.title}")
    return line


def _bar(score: int) -> str:
    filled = round(score / 100 * 16)
    return "#" * filled + "-" * (16 - filled)

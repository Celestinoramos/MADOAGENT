"""Terminal rendering for findings."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from mado.findings.schema import Finding


def render_findings_terminal(findings: list[Finding]) -> None:
    """Render normalized findings as a readable terminal table."""

    console = Console()
    if not findings:
        console.print("[green]No findings returned.[/green]")
        return

    table = Table(title="Madó findings")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="magenta", no_wrap=True)
    table.add_column("File", style="white")
    table.add_column("Line", style="white", no_wrap=True)
    table.add_column("Rule", style="white")
    table.add_column("Message", style="white")

    for finding in findings:
        severity = finding.severity_raw.upper()
        table.add_row(
            finding.id,
            severity,
            finding.file,
            str(finding.line) if finding.line is not None else "-",
            finding.rule_id or "-",
            finding.message_raw,
        )

    console.print(table)

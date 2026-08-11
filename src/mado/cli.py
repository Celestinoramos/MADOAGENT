"""Command-line interface for Madó."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

import typer
from rich.console import Console

from mado.explanations import explain_finding
from mado.orchestrator import run_orchestrator
from mado.report.renderer import render_findings_terminal

app = typer.Typer(
    add_completion=False,
    help="Madó - CLI de segurança local para developers",
    invoke_without_command=True,
)


@app.callback()
def main() -> None:
    """Entry point for the CLI group."""

    return None


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=True, dir_okay=True, readable=True),
    diff: bool = typer.Option(False, "--diff", help="Scan only files changed since the last commit"),
    format: str = typer.Option("terminal", "--format", case_sensitive=False),
) -> None:
    """Run Semgrep over a project and show normalized findings."""

    if format.lower() not in {"terminal", "json"}:
        raise typer.BadParameter("format must be terminal or json")

    try:
        findings = run_orchestrator(str(path), diff=diff)
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    if format.lower() == "json":
        typer.echo(json.dumps([asdict(finding) for finding in findings], indent=2, ensure_ascii=False))
        return

    render_findings_terminal(findings)


@app.command()
def explain(
    finding_id: str,
    path: Path = typer.Option(Path("."), "--path", exists=True, file_okay=True, dir_okay=True, readable=True),
) -> None:
    """Explain a specific finding by re-running the scan for the target path."""

    try:
        findings = run_orchestrator(str(path))
    except RuntimeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    finding = next((item for item in findings if item.id == finding_id), None)
    if finding is None:
        typer.echo(f"Finding {finding_id} not found under {path}", err=True)
        raise typer.Exit(code=1)

    explanation = explain_finding(finding)
    console = Console()
    console.print(f"[bold]Finding[/bold] {finding.id}")
    console.print(f"[bold]Location[/bold] {finding.file}:{finding.line if finding.line is not None else '-'}")
    console.print(f"[bold]Scanner[/bold] {finding.scanner}")
    console.print(f"[bold]Rule[/bold] {finding.rule_id or '-'}")
    console.print(f"[bold]CWE[/bold] {finding.cwe or '-'}")
    console.print(f"[bold]Severity[/bold] {explanation.severity}")
    console.print(f"[bold]Summary[/bold] {explanation.summary}")
    console.print(f"[bold]Root cause[/bold] {explanation.root_cause}")
    console.print(f"[bold]Impact[/bold] {explanation.impact}")
    console.print(f"[bold]Remediation[/bold] {explanation.remediation}")

    if explanation.references:
        console.print("[bold]References[/bold]")
        for reference in explanation.references:
            console.print(f"- {reference}")


if __name__ == "__main__":
    app()

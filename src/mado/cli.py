"""Command-line interface for Madó."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, replace
from pathlib import Path

import typer
from rich.console import Console

from mado.config import Config, load_config, load_config_file, render_example_config
from mado.explanations import explain_finding
from mado.explanations.knowledge_base import lookup_entry
from mado.findings.ignore import IgnoreList
from mado.findings.schema import Finding
from mado.graph.graph_orchestrator import GraphOrchestrator
from mado.graph.state import AbortScan, Target
from mado.orchestrator import run_scan
from mado.rag.retrieval import retrieve_context
from mado.llm.client import LlmClient, llm_enabled
from mado.report.models import Report
from mado.report.renderer import (
    render_report_json,
    render_report_markdown,
    render_report_terminal,
)
from mado.watch import WatchMode

app = typer.Typer(
    add_completion=False,
    help="Madó - CLI de segurança local para developers",
    invoke_without_command=True,
)

console = Console()
error_console = Console(stderr=True)


def _print_warnings(warnings: list[str]) -> None:
    for warning in warnings:
        error_console.print(f"[yellow]warning:[/yellow] {warning}")


def _resolve_config(path: Path, config_path: str | None) -> Config:
    if config_path:
        return load_config_file(config_path)
    return load_config(path)


@app.callback()
def main() -> None:
    """Entry point for the CLI group."""
    return None


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=True, dir_okay=True, readable=True),
    diff: bool = typer.Option(False, "--diff", help="Scan only files changed since the last commit"),
    severity: str = typer.Option(None, "--severity", help="Minimum severity (low|medium|high|critical)"),
    format: str = typer.Option("terminal", "--format", case_sensitive=False),
    target: str = typer.Option(None, "--target", help="Running application URL to scan dynamically"),
    openapi: str = typer.Option(None, "--openapi", help="Path to an OpenAPI spec for dynamic recon"),
    postman: str = typer.Option(None, "--postman", help="Path to a Postman collection for dynamic recon"),
    config_path: str = typer.Option(None, "--config", help="Explicit path to a .mado.yml file"),
    output: str = typer.Option(None, "--output", help="Write the report to a file"),
    watch: bool = typer.Option(False, "--watch", help="Watch the project and re-scan on changes"),
) -> None:
    """Scan a project (static) or a running application (dynamic)."""

    if format.lower() not in {"terminal", "json", "md"}:
        raise typer.BadParameter("format must be terminal, json or md")

    try:
        if target is not None:
            report = _scan_dynamic(target, openapi, postman, config_path)
        elif watch:
            _scan_watch(str(path), severity=severity, config_path=config_path)
            return
        else:
            report = _scan_static(str(path), diff=diff, severity=severity, config_path=config_path)
    except AbortScan as exc:
        error_console.print(f"[red]aborted:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except RuntimeError as exc:
        error_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    rendered = _render_report(report, format)
    if rendered is None:
        return
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered + "\n")


def _scan_watch(path: str, severity: str | None, config_path: str | None) -> None:
    config = _resolve_config(Path(path), config_path)
    if severity:
        config = replace(config, severity_threshold=severity)

    def trigger() -> None:
        result = run_scan(path, diff=True, config=config)
        _print_warnings(result.warnings)
        render_report_terminal(Report.from_findings(Path(path).resolve().name, result.findings))

    console.print(f"[bold]Madó watch[/bold] — a observar {Path(path).resolve()} (Ctrl-C para sair)")
    trigger()
    WatchMode(root=path, scan_callback=trigger).run()


def _scan_static(path: str, diff: bool, severity: str | None, config_path: str | None) -> Report:
    config = _resolve_config(Path(path), config_path)
    if severity:
        config = replace(config, severity_threshold=severity)
    result = run_scan(path, diff=diff, config=config)
    _print_warnings(result.warnings)
    return Report.from_findings(Path(path).resolve().name, result.findings)


def _scan_dynamic(target_url: str, openapi: str | None, postman: str | None, config_path: str | None) -> Report:
    target = Target(
        url=target_url,
        openapi_spec=openapi,
        postman_collection=postman,
    )
    orchestrator = GraphOrchestrator()
    if config_path:
        orchestrator.config = load_config_file(config_path)
    report = orchestrator.run(target)
    _print_warnings(orchestrator.last_warnings)
    return report


def _render_report(report: Report, format: str) -> str | None:
    if format == "json":
        return render_report_json(report)
    if format == "md":
        return render_report_markdown(report)
    render_report_terminal(report)
    return None


@app.command()
def explain(
    finding_id: str,
    path: Path = typer.Option(Path("."), "--path", exists=True, file_okay=True, dir_okay=True, readable=True),
) -> None:
    """Explain a specific finding by re-running the scan for the target path."""

    try:
        result = run_scan(str(path))
    except RuntimeError as exc:
        error_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _print_warnings(result.warnings)

    finding = next((item for item in result.findings if item.id == finding_id), None)
    if finding is None:
        error_console.print(f"Finding {finding_id} not found under {path}")
        raise typer.Exit(code=1)

    explanation = explain_finding(finding)
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


@app.command()
def ask(
    question: str = typer.Argument(..., help="Question about detected vulnerabilities"),
    finding_id: str | None = typer.Option(
        None, "--finding", help="Explain a specific finding by ID (requires scan first)"
    ),
    path: Path = typer.Option(Path("."), "--path", exists=True, file_okay=True, dir_okay=True, readable=True),
) -> None:
    """Ask a question about detected vulnerabilities, answered via RAG or LLM."""

    if finding_id:
        try:
            result = run_scan(str(path))
        except RuntimeError as exc:
            error_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=1) from exc

        _print_warnings(result.warnings)

        finding = next((item for item in result.findings if item.id == finding_id), None)
        if finding is None:
            error_console.print(f"Finding {finding_id} not found under {path}")
            raise typer.Exit(code=1)

        explanation = explain_finding(finding)
        console.print(f"[bold]Finding[/bold] {finding.id}")
        console.print(f"[bold]Question[/bold] {question}")
        console.print(f"[bold]Summary[/bold] {explanation.summary}")
        console.print(f"[bold]Root cause[/bold] {explanation.root_cause}")
        console.print(f"[bold]Impact[/bold] {explanation.impact}")
        console.print(f"[bold]Severity[/bold] {explanation.severity}")
        console.print(f"[bold]Remediation[/bold] {explanation.remediation}")

        if explanation.references:
            console.print("[bold]References[/bold]")
            for reference in explanation.references:
                console.print(f"- {reference}")
        return

    # General question - use RAG + LLM
    try:
        result = run_scan(str(path))
    except RuntimeError as exc:
        error_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _print_warnings(result.warnings)

    if not result.findings:
        error_console.print("[red]error:[/red] No findings detected. Run a scan first or provide --finding.")
        raise typer.Exit(code=1)

    # Use the first finding's context for the answer
    finding = result.findings[0]
    context = retrieve_context(finding)

    if llm_enabled():
        client = LlmClient()
        user_prompt = f"""Question: {question}

Finding context:
- Rule ID: {finding.rule_id or '-'}
- CWE: {finding.cwe or '-'}
- Severity: {finding.severity_raw}
- Message: {finding.message_raw}

Relevant OWASP/CWE context:
{chr(10).join(f'- {c}' for c in context)}

Please answer the question based on the above finding context."""
        try:
            response = client._get_client().messages.create(
                model=client.model,
                max_tokens=1024,
                system="""You are a security expert helping a developer understand a vulnerability. 
Provide a clear, concise answer based on the provided context. If the context doesn't contain the answer, 
say you don't have enough information rather than making things up.""",
                messages=[{"role": "user", "content": user_prompt}],
            )
        except Exception:
            error_console.print("[red]error:[/red] Failed to get LLM response.")
            raise typer.Exit(code=1) from exc

        text = "".join(
            block.text for block in response.content if getattr(block, "type", "") == "text"
        )
        console.print(f"[bold]Answer[/bold] {text}")
    else:
        # Fall back to knowledge base
        entry = lookup_entry(finding.cwe, finding.rule_id)
        console.print(f"[bold]Answer[/bold]")
        console.print(f"Summary: {entry.summary}")
        console.print(f"Root cause: {entry.root_cause}")
        console.print(f"Impact: {entry.impact}")
        console.print(f"Remediation: {entry.remediation}")
        if entry.references:
            console.print("[bold]References[/bold]")
            for ref in entry.references:
                console.print(f"- {ref}")


@app.command()
def report(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=True, dir_okay=True, readable=True),
    format: str = typer.Option("md", "--format", case_sensitive=False),
    output: str = typer.Option(None, "--output", help="Write the report to a file"),
) -> None:
    """Generate a report from a fresh scan of the project."""

    if format.lower() not in {"md", "json"}:
        raise typer.BadParameter("format must be md or json")

    try:
        result = run_scan(str(path))
    except RuntimeError as exc:
        error_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _print_warnings(result.warnings)
    report_data = Report.from_findings(Path(path).resolve().name, result.findings)
    rendered = render_report_json(report_data) if format == "json" else render_report_markdown(report_data)
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
    else:
        console.print(rendered)


@app.command()
def ignore(
    finding_id: str | None = typer.Argument(None, help="Finding id to ignore (false positive)"),
    path: Path = typer.Option(Path("."), "--path", exists=True, file_okay=True, dir_okay=True, readable=True),
    remove: str = typer.Option(None, "--remove", help="Remove a finding id from the ignore list"),
    show_list: bool = typer.Option(False, "--list", help="List ignored finding ids"),
    clear: bool = typer.Option(False, "--clear", help="Clear the whole ignore list"),
) -> None:
    """Manage the false-positive ignore list (.mado/ignore.json)."""

    ignore_list = IgnoreList(root=path)

    if clear:
        ignore_list.clear()
        console.print("[green]Ignore list cleared.[/green]")
        return

    if show_list:
        ids = ignore_list.all()
        if not ids:
            console.print("Ignore list is empty.")
            return
        console.print("Ignored findings:")
        for ignored_id in ids:
            console.print(f"- {ignored_id}")
        return

    if remove:
        if ignore_list.remove(remove):
            console.print(f"[green]Removed[/green] {remove} from the ignore list.")
        else:
            error_console.print(f"Finding {remove} was not in the ignore list.")
            raise typer.Exit(code=1)
        return

    if not finding_id:
        error_console.print("Provide a finding id, or use --list / --remove / --clear.")
        raise typer.Exit(code=1)

    try:
        result = run_scan(str(path))
    except RuntimeError as exc:
        error_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if not any(item.id == finding_id for item in result.findings):
        error_console.print(
            f"Finding {finding_id} not found in the scan of {path}. Check the id with 'mado scan' or 'mado explain'."
        )
        raise typer.Exit(code=1)

    if ignore_list.add(finding_id):
        console.print(f"[green]Ignored[/green] {finding_id} — will not appear in future scans.")
    else:
        console.print(f"{finding_id} is already in the ignore list.")


@app.command("config")
def config_cmd(
    init: bool = typer.Option(False, "--init", help="Create a .mado.yml with defaults"),
    path: Path = typer.Option(Path("."), "--path", exists=True, dir_okay=True),
) -> None:
    """Manage Madó configuration."""

    if init:
        destination = path / ".mado.yml"
        if destination.exists():
            error_console.print(f"[red]error:[/red] {destination} already exists")
            raise typer.Exit(code=1)
        destination.write_text(render_example_config(), encoding="utf-8")
        console.print(f"[green]Created[/green] {destination}")
        return

    console.print("Current configuration:")
    try:
        loaded = load_config(path)
    except RuntimeError as exc:
        error_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(json.dumps(asdict(loaded), indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    app()

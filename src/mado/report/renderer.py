"""Rendering for findings and reports: terminal, markdown, JSON."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.table import Table

from mado.findings.schema import Finding, normalize_severity
from mado.report.models import Report

_SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "unknown": "white",
}


def _severity_style(severity: str) -> str:
    return _SEVERITY_STYLES.get(severity, "white")


def render_findings_terminal(findings: list[Finding]) -> None:
    """Render normalized findings as a severity-colored terminal table."""

    console = Console()
    if not findings:
        console.print("[green]No findings returned.[/green]")
        return

    table = Table(title="Madó findings")
    table.add_column("Severity", no_wrap=True)
    table.add_column("File", style="white")
    table.add_column("Line", style="white", no_wrap=True)
    table.add_column("Rule", style="white")
    table.add_column("Message", style="white")

    for finding in findings:
        severity = normalize_severity(finding.severity_raw)
        table.add_row(
            f"[{_severity_style(severity)}]{severity.upper()}[/{_severity_style(severity)}]",
            finding.file,
            str(finding.line) if finding.line is not None else "-",
            finding.rule_id or "-",
            finding.message_raw,
        )

    console.print(table)


def render_findings_json(findings: list[Finding]) -> str:
    """Serialize findings to a JSON string."""
    report = Report.from_findings("", findings)
    payload = report.to_dict()
    payload.pop("target")
    payload.pop("generated_at")
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_findings_markdown(findings: list[Finding]) -> str:
    """Render findings to a Markdown string with one section per finding."""
    report = Report.from_findings("", findings)
    return render_report_markdown(report)


def render_report_terminal(report: Report) -> None:
    """Render a compiled report (summary + findings) to the terminal."""
    console = Console()
    console.print(f"[bold]Madó report[/bold] — {report.target}")
    console.print(f"Generated: {report.generated_at}")
    console.print()
    console.print("[bold]Summary by severity[/bold]")
    for severity, count in report.summary.items():
        if count:
            console.print(f"  [{_severity_style(severity)}]{severity}: {count}[/{_severity_style(severity)}]")
    console.print()
    render_findings_terminal(report.findings)


def render_report_markdown(report: Report) -> str:
    """Render a compiled report as Markdown."""
    lines: list[str] = [
        f"# Madó security report",
        "",
        f"- **Target:** {report.target}",
        f"- **Generated:** {report.generated_at}",
        "",
        "## Executive summary",
        "",
    ]
    total = sum(report.summary.values())
    lines.append(f"A total of **{total}** findings were identified.")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for severity, count in report.summary.items():
        if count:
            lines.append(f"| {severity} | {count} |")
    lines.append("")

    if not report.findings:
        lines.append("No findings returned.")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    for finding in report.findings:
        lines.append(f"### {finding.message_raw}")
        lines.append("")
        lines.append(f"- **Severity:** {normalize_severity(finding.severity_raw)}")
        lines.append(f"- **Scanner:** {finding.scanner}")
        lines.append(f"- **Location:** `{finding.file}:{finding.line if finding.line is not None else '-'}`")
        if finding.rule_id:
            lines.append(f"- **Rule:** `{finding.rule_id}`")
        if finding.cwe:
            lines.append(f"- **CWE:** {finding.cwe}")
        if finding.code_snippet:
            lines.append("")
            lines.append("```text")
            lines.append(str(finding.code_snippet))
            lines.append("```")
        if finding.explanation is not None:
            explanation = finding.explanation
            lines.append("")
            lines.append(f"**Summary:** {explanation.summary}")
            lines.append("")
            lines.append(f"**Root cause:** {explanation.root_cause}")
            lines.append("")
            lines.append(f"**Impact:** {explanation.impact}")
            lines.append("")
            lines.append(f"**Remediation:** {explanation.remediation}")
            if explanation.references:
                lines.append("")
                lines.append("**References:**")
                for reference in explanation.references:
                    lines.append(f"- {reference}")
        lines.append("")

    return "\n".join(lines)


def render_report_json(report: Report) -> str:
    """Serialize a compiled report as JSON."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def render_findings(findings: list[Finding], format: str) -> str | None:
    """Render findings in a given format, returning text for md/json."""
    if format == "json":
        return render_findings_json(findings)
    if format == "md":
        return render_findings_markdown(findings)
    render_findings_terminal(findings)
    return None


def serialize_report(report: Report, format: str) -> str:
    """Serialize a report in md/json; terminal reports render to the console."""
    if format == "json":
        return render_report_json(report)
    if format == "md":
        return render_report_markdown(report)
    render_report_terminal(report)
    return ""

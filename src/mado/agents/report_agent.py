"""Report agent: compiles a compliance-ready report from findings."""

from __future__ import annotations

from mado.findings.schema import Finding
from mado.report.models import Report


class ReportAgent:
    """Compile the final report with an executive summary."""

    def compile(self, target_label: str, findings: list[Finding]) -> Report:
        return Report.from_findings(target_label, findings)

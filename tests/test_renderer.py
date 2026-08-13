from __future__ import annotations

import json
import unittest

from mado.explanations.schema import FindingExplanation
from mado.findings.schema import Finding
from mado.report.models import Report, highest_severity, severity_counts
from mado.report.renderer import (
    render_findings_json,
    render_findings_markdown,
    render_report_json,
    render_report_markdown,
)


def _finding(severity: str, scanner: str = "semgrep") -> Finding:
    return Finding(
        id=f"f_{scanner}_{severity}",
        file="src/app.py",
        line=1,
        scanner=scanner,
        rule_id="r",
        cwe="CWE-89",
        severity_raw=severity,
        message_raw="Possible SQL injection",
        code_snippet="query = ...",
        explanation=FindingExplanation(
            summary="SQL injection summary",
            root_cause="untrusted input concatenated into SQL",
            impact="data exfiltration",
            severity="high",
            remediation="use parameters",
            references=["https://cwe.mitre.org/data/definitions/89.html"],
        ),
    )


class ReportModelTests(unittest.TestCase):
    def test_severity_counts(self) -> None:
        counts = severity_counts([_finding("ERROR"), _finding("WARNING"), _finding("ERROR")])
        self.assertEqual(counts["high"], 2)
        self.assertEqual(counts["medium"], 1)

    def test_highest_severity(self) -> None:
        self.assertEqual(highest_severity([_finding("WARNING"), _finding("ERROR")]), "high")
        self.assertIsNone(highest_severity([]))

    def test_report_from_findings(self) -> None:
        report = Report.from_findings("localhost", [_finding("ERROR")])
        self.assertEqual(report.target, "localhost")
        self.assertEqual(report.summary["high"], 1)


class RendererTests(unittest.TestCase):
    def test_render_markdown_contains_sections(self) -> None:
        markdown = render_findings_markdown([_finding("ERROR")])
        self.assertIn("# Madó security report", markdown)
        self.assertIn("Executive summary", markdown)
        self.assertIn("use parameters", markdown)

    def test_render_markdown_contains_finding_id(self) -> None:
        markdown = render_findings_markdown([_finding("ERROR")])
        self.assertIn("**ID:** `f_semgrep_ERROR`", markdown)

    def test_render_json_is_valid_and_complete(self) -> None:
        payload = json.loads(render_findings_json([_finding("ERROR")]))
        self.assertEqual(payload["findings"][0]["explanation"]["summary"], "SQL injection summary")
        self.assertEqual(payload["findings"][0]["cwe"], "CWE-89")

    def test_render_report_json(self) -> None:
        report = Report.from_findings("target", [_finding("ERROR")])
        payload = json.loads(render_report_json(report))
        self.assertIn("target", payload)
        self.assertIn("highest_severity", payload)

    def test_render_report_markdown(self) -> None:
        report = Report.from_findings("target", [_finding("ERROR")])
        markdown = render_report_markdown(report)
        self.assertIn("**Target:** target", markdown)


if __name__ == "__main__":
    unittest.main()

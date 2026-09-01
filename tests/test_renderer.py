from __future__ import annotations

import io
import json
import unittest
from unittest import mock

from rich.console import Console

from mado.explanations.schema import FindingExplanation
from mado.findings.schema import Finding
from mado.report import renderer
from mado.report.models import Report, highest_severity, severity_counts
from mado.report.renderer import (
    render_findings_json,
    render_findings_markdown,
    render_findings_terminal,
    render_report_json,
    render_report_markdown,
    render_report_sarif,
)

_LONG_RULE_ID = "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1"


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

    def test_render_report_sarif(self) -> None:
        report = Report.from_findings("target", [_finding("ERROR")])
        payload = json.loads(render_report_sarif(report))
        self.assertEqual(payload["version"], "2.1.0")
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Madó")
        self.assertEqual(run["results"][0]["ruleId"], "r")
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(
            run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            1,
        )


def _render_terminal(findings: list[Finding], width: int) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, width=width, height=40, no_color=True)
    with mock.patch.object(renderer, "Console", return_value=console):
        render_findings_terminal(findings)
    return buffer.getvalue()


class TerminalTableTests(unittest.TestCase):
    def _long_finding(self) -> Finding:
        finding = _finding("ERROR")
        finding.id = "f_8beb8d38bd"
        finding.rule_id = _LONG_RULE_ID
        finding.file = "src/mado/findings/an/unusually/deep/path/cache.py"
        return finding

    def test_all_columns_survive_unbreakable_tokens(self) -> None:
        for width in (80, 100, 140, 200):
            with self.subTest(width=width):
                output = _render_terminal([self._long_finding()], width)
                for header in ("Severity", "ID", "Location", "Issue"):
                    self.assertIn(header, output)

    def test_table_never_exceeds_console_width(self) -> None:
        for width in (80, 100, 140, 200):
            with self.subTest(width=width):
                output = _render_terminal([self._long_finding()], width)
                self.assertLessEqual(max(len(line) for line in output.splitlines()), width)

    def test_severity_and_id_are_never_truncated(self) -> None:
        for width in (80, 100, 140, 200):
            with self.subTest(width=width):
                output = _render_terminal([self._long_finding()], width)
                self.assertIn("HIGH", output)
                self.assertIn("f_8beb8d38bd", output)

    def test_row_content_is_present(self) -> None:
        output = _render_terminal([self._long_finding()], 200)
        self.assertIn("cache.py:1", output)
        self.assertIn("Possible SQL injection", output)
        self.assertIn(_LONG_RULE_ID, output)

    def test_narrow_terminal_falls_back_to_stacked_layout(self) -> None:
        output = _render_terminal([self._long_finding()], 40)
        self.assertNotIn("┏", output)
        self.assertIn("f_8beb8d38bd", output)
        self.assertIn("Possible SQL injection", output)

    def test_empty_findings(self) -> None:
        self.assertIn("No findings returned.", _render_terminal([], 80))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from mado.cli import app
from mado.findings.schema import Finding
from mado.orchestrator import ScanResult


class CliTests(unittest.TestCase):
    def test_scan_reports_scanner_error_without_traceback(self) -> None:
        runner = CliRunner()

        with patch(
            "mado.cli.run_scan",
            side_effect=RuntimeError("Semgrep binary not found. Install semgrep and ensure it is on PATH."),
        ):
            result = runner.invoke(app, ["scan", "."])

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Semgrep binary not found", result.stderr)
        self.assertNotIn("Traceback", result.stdout)

    def test_scan_returns_zero_without_findings(self) -> None:
        runner = CliRunner()
        with patch("mado.cli.run_scan", return_value=ScanResult(findings=[])):
            result = runner.invoke(app, ["scan", ".", "--format", "json"])
        self.assertEqual(result.exit_code, 0)

    def test_scan_returns_one_with_findings_after_rendering(self) -> None:
        runner = CliRunner()
        finding = Finding(
            id="f_test",
            file="src/app.py",
            line=1,
            scanner="semgrep",
            rule_id="test",
            cwe=None,
            severity_raw="HIGH",
            message_raw="problem",
        )
        with patch("mado.cli.run_scan", return_value=ScanResult(findings=[finding])):
            result = runner.invoke(app, ["scan", ".", "--format", "json"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn('"id": "f_test"', result.stdout)


if __name__ == "__main__":
    unittest.main()

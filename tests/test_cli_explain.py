from __future__ import annotations

import re
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from mado.cli import app
from mado.findings.schema import Finding
from mado.orchestrator import ScanResult

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


class CliExplainTests(unittest.TestCase):
    def test_explain_renders_structured_output(self) -> None:
        runner = CliRunner()
        finding = Finding(
            id="f_test",
            file="src/app.py",
            line=12,
            scanner="semgrep",
            rule_id="python.sql.injection",
            cwe="CWE-89",
            severity_raw="ERROR",
            message_raw="Possible SQL injection",
            code_snippet="query = f'SELECT * FROM users WHERE id={user_id}'",
        )

        with patch("mado.cli.run_scan", return_value=ScanResult(findings=[finding])):
            result = runner.invoke(app, ["explain", "f_test", "--path", "."])

        self.assertEqual(result.exit_code, 0)
        stdout = _strip_ansi(result.stdout)
        self.assertIn("Finding f_test", stdout)
        self.assertIn("SQL injection", stdout)
        self.assertIn("parameterized", stdout)


if __name__ == "__main__":
    unittest.main()

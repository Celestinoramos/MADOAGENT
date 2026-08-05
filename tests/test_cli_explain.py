from __future__ import annotations

import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from mado.cli import app
from mado.findings.schema import Finding


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

        with patch("mado.cli.run_orchestrator", return_value=[finding]):
            result = runner.invoke(app, ["explain", "f_test", "--path", "."])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Finding f_test", result.stdout)
        self.assertIn("SQL injection", result.stdout)
        self.assertIn("parameterized", result.stdout)


if __name__ == "__main__":
    unittest.main()
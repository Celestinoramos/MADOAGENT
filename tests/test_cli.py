from __future__ import annotations

import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from mado.cli import app


class CliTests(unittest.TestCase):
    def test_scan_reports_scanner_error_without_traceback(self) -> None:
        runner = CliRunner()

        with patch("mado.cli.run_orchestrator", side_effect=RuntimeError("Semgrep binary not found. Install semgrep and ensure it is on PATH.")):
            result = runner.invoke(app, ["scan", "."])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Semgrep binary not found", result.stderr)
        self.assertNotIn("Traceback", result.stdout)


if __name__ == "__main__":
    unittest.main()
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from mado.scanners.semgrep import SemgrepScanner


class _CompletedProcess:
    def __init__(self, returncode: int, stdout: str, stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class SemgrepScannerTests(unittest.TestCase):
    @patch("mado.scanners.semgrep.shutil.which", return_value="/usr/bin/semgrep")
    @patch("mado.scanners.semgrep.subprocess.run")
    def test_run_normalizes_results(self, mock_run: object, _mock_which: object) -> None:
        payload = {
            "results": [
                {
                    "path": "src/app.py",
                    "start": {"line": 10},
                    "check_id": "python.security.audit.sql_injection",
                    "extra": {"message": "SQL injection", "severity": "ERROR"},
                }
            ]
        }
        cast_run = mock_run
        cast_run.return_value = _CompletedProcess(1, json.dumps(payload))

        findings = SemgrepScanner().run(".")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file, "src/app.py")
        self.assertEqual(findings[0].line, 10)
        self.assertEqual(findings[0].message_raw, "SQL injection")

    @patch("mado.scanners.semgrep.shutil.which", return_value=None)
    @patch("mado.scanners.semgrep.Path.exists", return_value=False)
    @patch("mado.scanners.semgrep.importlib.util.find_spec", return_value=None)
    def test_run_raises_runtime_error_when_semgrep_is_missing(
        self,
        _mock_find_spec: object,
        _mock_exists: object,
        _mock_which: object,
    ) -> None:
        with self.assertRaisesRegex(RuntimeError, "Semgrep binary not found"):
            SemgrepScanner().run(".")


if __name__ == "__main__":
    unittest.main()

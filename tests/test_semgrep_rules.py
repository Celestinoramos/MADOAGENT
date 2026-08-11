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


class SemgrepRulesTests(unittest.TestCase):
    @patch("mado.scanners.semgrep.shutil.which", return_value="/usr/bin/semgrep")
    @patch("mado.scanners.semgrep.subprocess.run")
    def test_detects_os_system(self, mock_run: object, _mock_which: object) -> None:
        payload = {
            "results": [
                {
                    "path": "src/app.py",
                    "start": {"line": 5},
                    "check_id": "mado.python.os-system",
                    "extra": {"message": "Avoid os.system()", "severity": "WARNING"},
                }
            ]
        }
        mock_run.return_value = _CompletedProcess(1, json.dumps(payload))

        findings = SemgrepScanner().run(".")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "mado.python.os-system")

    @patch("mado.scanners.semgrep.shutil.which", return_value="/usr/bin/semgrep")
    @patch("mado.scanners.semgrep.subprocess.run")
    def test_detects_requests_verify_false(self, mock_run: object, _mock_which: object) -> None:
        payload = {
            "results": [
                {
                    "path": "src/client.py",
                    "start": {"line": 42},
                    "check_id": "mado.python.requests-verify-false",
                    "extra": {"message": "verify=False used", "severity": "ERROR"},
                }
            ]
        }
        mock_run.return_value = _CompletedProcess(1, json.dumps(payload))

        findings = SemgrepScanner().run(".")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "mado.python.requests-verify-false")


if __name__ == "__main__":
    unittest.main()

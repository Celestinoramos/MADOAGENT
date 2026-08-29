from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from mado.dast_scanners.zap import ZapScanner


class _CompletedProcess:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


_ALERT = {
    "site": [
        {
            "alerts": [
                {
                    "alert": "SQL Injection",
                    "riskdesc": "High (Medium)",
                    "cweid": 89,
                    "url": "http://localhost:8000/users?id=1",
                    "desc": "SQL injection may be possible",
                }
            ]
        }
    ]
}


def _write_report_from_docker_command(command: list[str], payload: dict) -> None:
    volume = command[command.index("-v") + 1]
    workdir = volume[: -len(":/zap/wrk/:rw")]
    Path(workdir, "zap_report.json").write_text(json.dumps(payload), encoding="utf-8")


class ZapScannerTests(unittest.TestCase):
    @patch("mado.dast_scanners.zap.docker_available", return_value=True)
    @patch("mado.dast_scanners.zap.subprocess.run")
    def test_exit_code_one_still_parses_alerts(self, mock_run: object, _docker: object) -> None:
        def fake_run(command, capture_output, text):
            _write_report_from_docker_command(command, _ALERT)
            return _CompletedProcess(1)

        mock_run.side_effect = fake_run  # type: ignore[attr-defined]
        findings = ZapScanner().run("http://localhost:8000")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].scanner, "zap")
        self.assertEqual(findings[0].cwe, "CWE-89")

    @patch("mado.dast_scanners.zap.docker_available", return_value=True)
    @patch("mado.dast_scanners.zap.subprocess.run")
    def test_exit_code_two_still_parses_alerts(self, mock_run: object, _docker: object) -> None:
        def fake_run(command, capture_output, text):
            _write_report_from_docker_command(command, _ALERT)
            return _CompletedProcess(2)

        mock_run.side_effect = fake_run  # type: ignore[attr-defined]
        findings = ZapScanner().run("http://localhost:8000")
        self.assertEqual(len(findings), 1)

    @patch("mado.dast_scanners.zap.docker_available", return_value=True)
    @patch("mado.dast_scanners.zap.subprocess.run")
    def test_exit_code_three_raises(self, mock_run: object, _docker: object) -> None:
        mock_run.return_value = _CompletedProcess(3, stderr="ZAP crashed")  # type: ignore[attr-defined]
        with self.assertRaisesRegex(RuntimeError, "ZAP baseline execution failed"):
            ZapScanner().run("http://localhost:8000")

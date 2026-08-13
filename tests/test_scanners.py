from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mado.scanners.bandit import BanditScanner
from mado.scanners.dependencies import NpmAuditScanner, PipAuditScanner
from mado.scanners.gitleaks import GitleaksScanner


class _CompletedProcess:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class BanditScannerTests(unittest.TestCase):
    @patch("mado.scanners.bandit.resolve_binary", return_value="/usr/bin/bandit")
    @patch("mado.scanners.bandit.subprocess.run")
    def test_run_normalizes_results(self, mock_run: object, _mock_resolve: object) -> None:
        payload = {
            "results": [
                {
                    "filename": "src/app.py",
                    "line_number": 3,
                    "test_id": "B602",
                    "issue_text": "shell=True",
                    "issue_severity": "HIGH",
                    "code": ["subprocess.run(cmd, shell=True)"],
                }
            ]
        }
        mock_run.return_value = _CompletedProcess(0, json.dumps(payload))  # type: ignore[assignment]
        findings = BanditScanner().run(".")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].scanner, "bandit")
        self.assertEqual(findings[0].line, 3)

    @patch("mado.scanners.bandit.resolve_binary", return_value=None)
    def test_missing_binary_raises(self, _mock_resolve: object) -> None:
        with self.assertRaisesRegex(RuntimeError, "Bandit binary not found"):
            BanditScanner().run(".")

    @patch("mado.scanners.bandit.resolve_binary", return_value="/usr/bin/bandit")
    @patch("mado.scanners.bandit.subprocess.run")
    def test_run_passes_exclude_flag(self, mock_run: object, _mock_resolve: object) -> None:
        mock_run.return_value = _CompletedProcess(0, json.dumps({"results": []}))  # type: ignore[assignment]
        BanditScanner(exclude=(".venv", ".git")).run(".")
        command = mock_run.call_args.args[0]  # type: ignore[attr-defined]
        self.assertIn("--exclude", command)
        self.assertIn(".venv,.git", command)


class GitleaksScannerTests(unittest.TestCase):
    @patch("mado.scanners.gitleaks.resolve_binary", return_value="/usr/bin/gitleaks")
    def test_run_normalizes_report(self, _mock_resolve: object) -> None:
        findings_payload = {
            "Findings": [
                {
                    "RuleID": "generic-api-key",
                    "Description": "Detected API key",
                    "StartLine": 5,
                    "File": "config.py",
                    "Secret": "sk_live_x",
                }
            ]
        }

        def fake_run(command, capture_output, text):
            report_path = command[command.index("--report-path") + 1]
            Path(report_path).write_text(json.dumps(findings_payload), encoding="utf-8")
            return _CompletedProcess(1)

        with patch("mado.scanners.gitleaks.subprocess.run", side_effect=fake_run):
            findings = GitleaksScanner().run(".")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].scanner, "gitleaks")
        self.assertEqual(findings[0].cwe, "CWE-798")
        self.assertEqual(findings[0].file, "config.py")

    @patch("mado.scanners.gitleaks.resolve_binary", return_value=None)
    def test_missing_binary_raises(self, _mock_resolve: object) -> None:
        with self.assertRaisesRegex(RuntimeError, "Gitleaks binary not found"):
            GitleaksScanner().run(".")


class PipAuditScannerTests(unittest.TestCase):
    @patch("mado.scanners.dependencies.resolve_binary", return_value="/usr/bin/pip-audit")
    @patch("mado.scanners.dependencies.subprocess.run")
    def test_run_normalizes_results(self, mock_run: object, _mock_resolve: object) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8")
            payload = {
                "dependencies": [
                    {
                        "name": "requests",
                        "version": "2.19.1",
                        "vulns": [
                            {
                                "id": "CVE-2018-18074",
                                "severity": "high",
                                "description": "mishandles cookies",
                                "fix_versions": ["2.20.0"],
                            }
                        ],
                    }
                ]
            }
            mock_run.return_value = _CompletedProcess(0, json.dumps(payload))  # type: ignore[assignment]
            findings = PipAuditScanner().run(str(root))
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].rule_id, "CVE-2018-18074")


class NpmAuditScannerTests(unittest.TestCase):
    @patch("mado.scanners.dependencies.resolve_binary", return_value="/usr/bin/npm")
    @patch("mado.scanners.dependencies.subprocess.run")
    def test_run_normalizes_results(self, mock_run: object, _mock_resolve: object) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text("{}", encoding="utf-8")
            payload = {
                "vulnerabilities": {
                    "lodash": {"severity": "high", "via": [{"title": "Prototype Pollution", "cwe": ["CWE-1321"]}]}
                }
            }
            mock_run.return_value = _CompletedProcess(1, json.dumps(payload))  # type: ignore[assignment]
            findings = NpmAuditScanner().run(str(root))
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].scanner, "npm-audit")
            self.assertEqual(findings[0].cwe, "CWE-1321")


if __name__ == "__main__":
    unittest.main()

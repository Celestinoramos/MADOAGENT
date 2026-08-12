from __future__ import annotations

import unittest

from mado.findings.schema import (
    meets_severity_threshold,
    normalize_bandit_result,
    normalize_gitleaks_result,
    normalize_npm_vuln,
    normalize_nuclei_result,
    normalize_pip_audit_vuln,
    normalize_severity,
    normalize_zap_alert,
)


class NormalizerTests(unittest.TestCase):
    def test_bandit(self) -> None:
        finding = normalize_bandit_result(
            {
                "filename": "src/app.py",
                "line_number": 7,
                "test_id": "B602",
                "test_name": "subprocess_popen_with_shell_equals_true",
                "issue_text": "subprocess call with shell=True",
                "issue_severity": "HIGH",
                "issue_confidence": "MEDIUM",
                "code": ["cmd = subprocess.Popen(sh, shell=True)"],
                "issue_cwe": [{"id": "CWE-78"}],
            }
        )
        self.assertEqual(finding.scanner, "bandit")
        self.assertEqual(finding.file, "src/app.py")
        self.assertEqual(finding.line, 7)
        self.assertEqual(finding.cwe, "CWE-78")
        self.assertEqual(finding.severity_raw, "HIGH")
        self.assertEqual(finding.rule_id, "B602")
        self.assertIn("shell=True", finding.code_snippet)

    def test_gitleaks(self) -> None:
        finding = normalize_gitleaks_result(
            {
                "RuleID": "aws-access-token",
                "Description": "AWS Access Token",
                "StartLine": 12,
                "File": "config.py",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "Match": "key=AKIAIOSFODNN7EXAMPLE",
            }
        )
        self.assertEqual(finding.scanner, "gitleaks")
        self.assertEqual(finding.cwe, "CWE-798")
        self.assertEqual(finding.line, 12)
        self.assertIn("AWS Access Token", finding.message_raw)

    def test_pip_audit(self) -> None:
        dependency = {"name": "requests", "version": "2.19.1", "vulns": []}
        vuln = {
            "id": "CVE-2018-18074",
            "severity": "high",
            "description": "Requests up to 2.19.1 mishandles cookies",
            "fix_versions": ["2.20.0"],
            "aliases": [],
        }
        finding = normalize_pip_audit_vuln(dependency, vuln, "requirements.txt")
        self.assertEqual(finding.scanner, "pip-audit")
        self.assertEqual(finding.rule_id, "CVE-2018-18074")
        self.assertEqual(finding.cwe, "CWE-1104")
        self.assertEqual(finding.severity_raw, "HIGH")
        self.assertIn("requests==2.19.1", finding.message_raw)

    def test_npm_vuln(self) -> None:
        info = {
            "severity": "high",
            "range": "<=0.1.0",
            "isDirect": True,
            "via": [{"title": "Prototype Pollution", "url": "https://github.com/advisories/1", "cwe": ["CWE-1321"]}],
        }
        finding = normalize_npm_vuln("lodash", info, "package-lock.json")
        self.assertEqual(finding.scanner, "npm-audit")
        self.assertEqual(finding.cwe, "CWE-1321")
        self.assertEqual(finding.severity_raw, "HIGH")
        self.assertIn("Prototype Pollution", finding.message_raw)

    def test_zap_alert(self) -> None:
        finding = normalize_zap_alert(
            {
                "alert": "SQL Injection",
                "riskdesc": "High (Medium)",
                "cweid": 89,
                "url": "http://localhost:8000/users?id=1",
                "desc": "SQL injection may be possible",
                "solution": "Use parameterized queries",
            }
        )
        self.assertEqual(finding.scanner, "zap")
        self.assertEqual(finding.cwe, "CWE-89")
        self.assertEqual(finding.severity_raw, "HIGH")
        self.assertIn("SQL Injection", finding.message_raw)

    def test_nuclei(self) -> None:
        finding = normalize_nuclei_result(
            {
                "template-id": "exposed-env",
                "info": {"name": "Exposed .env file", "severity": "medium", "tags": "config,exposure"},
                "matched-at": "http://localhost:8000/.env",
                "type": "http",
            }
        )
        self.assertEqual(finding.scanner, "nuclei")
        self.assertEqual(finding.severity_raw, "MEDIUM")
        self.assertEqual(finding.file, "http://localhost:8000/.env")

    def test_severity_helpers(self) -> None:
        self.assertEqual(normalize_severity("ERROR"), "high")
        self.assertEqual(normalize_severity("WARNING"), "medium")
        self.assertTrue(meets_severity_threshold("high", "medium"))
        self.assertFalse(meets_severity_threshold("low", "medium"))


if __name__ == "__main__":
    unittest.main()

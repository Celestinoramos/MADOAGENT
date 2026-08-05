from __future__ import annotations

import unittest

from mado.findings.schema import normalize_semgrep_result


class NormalizeSemgrepResultTests(unittest.TestCase):
    def test_extracts_core_fields(self) -> None:
        finding = normalize_semgrep_result(
            {
                "path": "src/app.py",
                "start": {"line": 42},
                "check_id": "python.sql.injection",
                "extra": {
                    "message": "Possible SQL injection",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89"]},
                    "lines": "query = f'SELECT * FROM users WHERE id={user_id}'",
                },
            }
        )

        self.assertEqual(finding.file, "src/app.py")
        self.assertEqual(finding.line, 42)
        self.assertEqual(finding.scanner, "semgrep")
        self.assertEqual(finding.rule_id, "python.sql.injection")
        self.assertEqual(finding.cwe, "CWE-89")
        self.assertEqual(finding.severity_raw, "ERROR")
        self.assertEqual(finding.message_raw, "Possible SQL injection")
        self.assertEqual(finding.code_snippet, "query = f'SELECT * FROM users WHERE id={user_id}'")
        self.assertTrue(finding.id.startswith("f_"))


if __name__ == "__main__":
    unittest.main()

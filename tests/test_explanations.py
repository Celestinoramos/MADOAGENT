from __future__ import annotations

import unittest

from mado.explanations import explain_finding
from mado.findings.schema import Finding


class ExplainFindingTests(unittest.TestCase):
    def test_uses_cwe_knowledge_base_entry(self) -> None:
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

        explanation = explain_finding(finding)

        self.assertEqual(explanation.severity, "high")
        self.assertIn("SQL injection", explanation.summary)
        self.assertIn("parameterized", explanation.remediation)
        self.assertTrue(explanation.references)


if __name__ == "__main__":
    unittest.main()
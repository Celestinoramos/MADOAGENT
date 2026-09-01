from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from mado.explanations import explain_finding
from mado.findings.cache import ExplanationCache
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

    def test_llm_portuguese_severity_is_normalized(self) -> None:
        finding = Finding(
            id="f_test",
            file="src/app.py",
            line=12,
            scanner="semgrep",
            rule_id="python.sql.injection",
            cwe="CWE-89",
            severity_raw="ERROR",
            message_raw="Possible SQL injection",
        )
        payload = {
            "summary": "SQL injection",
            "root_cause": "string concat",
            "impact": "data leak",
            "severity": "alta",
            "remediation": "use parameters",
            "references": [],
        }
        with (
            patch("mado.explanations.engine.llm_enabled", return_value=True),
            patch("mado.explanations.engine.retrieve_context", return_value=[]),
            patch("mado.explanations.engine.LlmClient") as mock_client,
        ):
            mock_client.return_value.explain.return_value = payload
            with tempfile.TemporaryDirectory() as tmp:
                explanation = explain_finding(finding, cache=ExplanationCache(root=tmp, ttl_days=None))
        self.assertEqual(explanation.severity, "high")


if __name__ == "__main__":
    unittest.main()

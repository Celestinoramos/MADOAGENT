from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mado.explanations import explain_finding
from mado.findings.cache import ExplanationCache
from mado.findings.schema import Finding


class CacheTests(unittest.TestCase):
    def test_get_set_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = ExplanationCache(root=tmp)
            finding = Finding(
                id="f1",
                file="src/app.py",
                line=1,
                scanner="semgrep",
                rule_id="r",
                cwe="CWE-89",
                severity_raw="ERROR",
                message_raw="SQL injection",
            )
            self.assertIsNone(cache.get(finding))
            cache.set(finding, {"summary": "cached"})
            self.assertEqual(cache.get(finding)["summary"], "cached")

    def test_persists_to_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = ExplanationCache(root=tmp)
            finding = Finding(
                id="f2",
                file="src/app.py",
                line=2,
                scanner="semgrep",
                rule_id="r",
                cwe="CWE-89",
                severity_raw="ERROR",
                message_raw="SQL injection",
            )
            cache.set(finding, {"summary": "persisted"})
            cache.save()

            reloaded = ExplanationCache(root=tmp)
            self.assertEqual(reloaded.get(finding)["summary"], "persisted")
            self.assertTrue((Path(tmp) / ".mado" / "cache.json").exists())


class ExplanationCacheIntegrationTests(unittest.TestCase):
    @patch("mado.explanations.engine.llm_enabled", return_value=False)
    def test_explain_uses_cache_on_second_call(self, _mock_llm: object) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = ExplanationCache(root=tmp)
            finding = Finding(
                id="f3",
                file="src/app.py",
                line=3,
                scanner="semgrep",
                rule_id="python.sql.injection",
                cwe="CWE-89",
                severity_raw="ERROR",
                message_raw="SQL injection",
            )
            first = explain_finding(finding, cache=cache)
            self.assertIn("SQL injection", first.summary)

            # Force a different payload into the cache and verify it is reused.
            cache.set(finding, {"summary": "from-cache", "root_cause": "r", "impact": "i",
                                "severity": "low", "remediation": "x"})
            second = explain_finding(finding, cache=cache)
            self.assertEqual(second.summary, "from-cache")


if __name__ == "__main__":
    unittest.main()

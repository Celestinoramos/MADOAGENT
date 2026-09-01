from __future__ import annotations

import tempfile
import unittest

from mado.explanations.schema import FindingExplanation
from mado.findings.schema import Finding
from mado.findings.store import LastScanStore
from mado.report.models import Report


class LastScanStoreTests(unittest.TestCase):
    def test_round_trip_preserves_findings_and_explanations(self) -> None:
        finding = Finding(
            id="f_test",
            file="src/app.py",
            line=12,
            scanner="semgrep",
            rule_id="rule",
            cwe="CWE-89",
            severity_raw="ERROR",
            message_raw="SQL injection",
            explanation=FindingExplanation(
                summary="SQL injection",
                root_cause="unsafe query",
                impact="data leak",
                severity="high",
                remediation="parameterize",
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            store = LastScanStore(tmp)
            store.save(Report.from_findings("demo", [finding]))
            loaded = store.load()

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.target, "demo")
        self.assertEqual(loaded.findings[0].id, "f_test")
        self.assertEqual(loaded.findings[0].explanation.summary, "SQL injection")

    def test_invalid_or_missing_store_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = LastScanStore(tmp)
            self.assertIsNone(store.load())
            store.path.parent.mkdir(parents=True)
            store.path.write_text('{"version": 999}', encoding="utf-8")
            self.assertIsNone(store.load())

from __future__ import annotations

import unittest
from unittest.mock import patch

from mado.findings.schema import Finding
from mado.graph.authorization import confirm_authorization, require_authorization
from mado.graph.graph_orchestrator import GraphOrchestrator
from mado.graph.state import AbortScan, Target


class AuthorizationTests(unittest.TestCase):
    def test_confirmation_required(self) -> None:
        target = Target(url="http://localhost:8000")
        self.assertTrue(confirm_authorization(target, prompt=lambda _: "y"))
        self.assertFalse(confirm_authorization(target, prompt=lambda _: "n"))

    def test_abort_when_not_confirmed(self) -> None:
        target = Target(url="http://localhost:8000")
        with self.assertRaisesRegex(AbortScan, "autorização não confirmada"):
            require_authorization(target, prompt=lambda _: "n")


class GraphOrchestratorTests(unittest.TestCase):
    @patch("mado.agents.dast.ZapScanner.is_available", return_value=True)
    @patch("mado.agents.dast.NucleiScanner.is_available", return_value=False)
    def test_dynamic_run_compiles_report(self, _mock_nuclei: object, _mock_zap: object) -> None:
        zap_finding = Finding(
            id="zap1",
            file="http://localhost:8000/users?id=1",
            line=None,
            scanner="zap",
            rule_id="WASC-19",
            cwe="CWE-89",
            severity_raw="HIGH",
            message_raw="SQL Injection possible",
        )

        with patch("mado.agents.dast.ZapScanner.run", return_value=[zap_finding]) as mock_run:
            orchestrator = GraphOrchestrator()
            report = orchestrator.run(
                Target(url="http://localhost:8000"),
                confirm_prompt=lambda _: "y",
            )

        mock_run.assert_called_once_with("http://localhost:8000")
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].scanner, "zap")
        self.assertTrue(report.findings[0].explanation is not None)
        self.assertIn("nuclei", " ".join(orchestrator.last_warnings))

    def test_local_code_mode_runs_static_scan(self) -> None:
        with patch("mado.graph.graph_orchestrator.run_scan") as mock_scan:
            from mado.orchestrator import ScanResult

            mock_scan.return_value = ScanResult(
                findings=[
                    Finding(
                        id="s1",
                        file="src/app.py",
                        line=1,
                        scanner="semgrep",
                        rule_id="r",
                        cwe="CWE-89",
                        severity_raw="ERROR",
                        message_raw="SQL injection",
                    )
                ]
            )
            report = GraphOrchestrator().run(Target(path="/tmp/nonexistent-project"))
            mock_scan.assert_called_once()
        self.assertEqual(report.findings[0].scanner, "semgrep")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mado.config import Config
from mado.findings.schema import Finding
from mado.orchestrator import ScanResult, run_orchestrator, run_scan


class _FakeScanner:
    name = "fake"

    def __init__(self, findings: list[Finding]) -> None:
        self._findings = findings

    def run(self, path: str) -> list[Finding]:
        return self._findings


def _finding(severity: str) -> Finding:
    return Finding(
        id=f"f_{severity}",
        file="src/app.py",
        line=1,
        scanner="fake",
        rule_id="r",
        cwe="CWE-89",
        severity_raw=severity,
        message_raw="message",
    )


class OrchestratorTests(unittest.TestCase):
    @patch("mado.explanations.engine.llm_enabled", return_value=False)
    def test_run_scan_returns_normalized_findings(self, _mock_llm: object) -> None:
        result = run_scan(".", scanners=[_FakeScanner([_finding("ERROR")])])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity_raw, "ERROR")
        self.assertIsNotNone(result.findings[0].explanation)

    @patch("mado.explanations.engine.llm_enabled", return_value=False)
    def test_severity_threshold_filters_findings(self, _mock_llm: object) -> None:
        config = Config(severity_threshold="medium")
        scanner = _FakeScanner([_finding("INFO"), _finding("ERROR")])
        result = run_scan(".", scanners=[scanner], config=config)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity_raw, "ERROR")

    @patch("mado.explanations.engine.llm_enabled", return_value=False)
    def test_ignore_paths_filter(self, _mock_llm: object) -> None:
        low = _finding("ERROR")
        low.file = "tests/test_app.py"
        config = Config(ignore_paths=["tests/"])
        result = run_scan(".", scanners=[_FakeScanner([low, _finding("ERROR")])], config=config)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].file, "src/app.py")

    @patch("mado.explanations.engine.llm_enabled", return_value=False)
    def test_scanner_error_becomes_warning(self, _mock_llm: object) -> None:
        class _BoomScanner:
            name = "boom"

            def run(self, path: str) -> list[Finding]:
                raise RuntimeError("boom failed")

        result = run_scan(".", scanners=[_BoomScanner()])
        self.assertEqual(result.findings, [])
        self.assertTrue(any("boom" in warning for warning in result.warnings))

    @patch("mado.explanations.engine.llm_enabled", return_value=False)
    def test_diff_mode_runs_per_changed_file(self, _mock_llm: object) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("x = 1\n", encoding="utf-8")

            with patch("mado.orchestrator._git_changed_files", return_value=[str(root / "app.py")]):
                scanner = _FakeScanner([_finding("ERROR")])
                result = run_scan(str(root), diff=True, scanners=[scanner])
                self.assertEqual(len(result.findings), 1)

    @patch("mado.explanations.engine.llm_enabled", return_value=False)
    def test_non_code_findings_are_filtered(self, _mock_llm: object) -> None:
        in_markdown = _finding("ERROR")
        in_markdown.file = "README.md"
        config = Config(code_extensions=[".py"])
        result = run_scan(".", scanners=[_FakeScanner([_finding("ERROR"), in_markdown])], config=config)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].file, "src/app.py")

    @patch("mado.explanations.engine.llm_enabled", return_value=False)
    def test_secrets_scanner_exempt_from_code_filter(self, _mock_llm: object) -> None:
        secret = _finding("ERROR")
        secret.file = "README.md"
        secret.scanner = "gitleaks"
        config = Config(code_extensions=[".py"])
        result = run_scan(".", scanners=[_FakeScanner([secret])], config=config)
        self.assertEqual(len(result.findings), 1)

    @patch("mado.explanations.engine.llm_enabled", return_value=False)
    def test_empty_code_extensions_disables_filter(self, _mock_llm: object) -> None:
        in_markdown = _finding("ERROR")
        in_markdown.file = "README.md"
        config = Config(code_extensions=[])
        result = run_scan(".", scanners=[_FakeScanner([in_markdown])], config=config)
        self.assertEqual(len(result.findings), 1)

    def test_run_orchestrator_backwards_compat(self) -> None:
        with patch("mado.orchestrator.run_scan") as mock_scan:
            mock_scan.return_value = ScanResult(findings=[_finding("ERROR")])
            findings = run_orchestrator(".")
            self.assertEqual(len(findings), 1)

    def test_run_scan_loads_project_env(self) -> None:
        with patch("mado.orchestrator.load_project_env") as mock_env:
            with patch("mado.explanations.engine.llm_enabled", return_value=False):
                run_scan(".", scanners=[])
                mock_env.assert_called_once()


if __name__ == "__main__":
    unittest.main()

"""Gitleaks scanner adapter (secret detection)."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from mado.findings.schema import Finding, normalize_gitleaks_result


@dataclass(slots=True)
class GitleaksScanner:
    """Run Gitleaks and normalize its JSON report."""

    name: str = "gitleaks"

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("gitleaks") is not None

    def run(self, path: str) -> list[Finding]:
        if not self.is_available():
            raise RuntimeError("Gitleaks binary not found. Install gitleaks and ensure it is on PATH.")

        target = Path(path).resolve()
        if target.is_file():
            target = target.parent

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as report_file:
            report_path = report_file.name

        command = [
            "gitleaks",
            "detect",
            "--source",
            str(target),
            "--no-git",
            "--report-format",
            "json",
            "--report-path",
            report_path,
        ]
        completed = subprocess.run(command, capture_output=True, text=True)

        # Gitleaks exits 1 when findings are found — that is a successful run.
        if completed.returncode not in (0, 1):
            details = completed.stderr.strip() or completed.stdout.strip() or "gitleaks exited with an unexpected error"
            raise RuntimeError(f"Gitleaks execution failed (exit code {completed.returncode}): {details}")

        report: dict = {}
        try:
            report = json.loads(Path(report_path).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            report = {}
        finally:
            Path(report_path).unlink(missing_ok=True)

        findings: list[Finding] = []
        for raw_finding in report.get("Findings", []):
            if not isinstance(raw_finding, dict):
                continue
            try:
                findings.append(normalize_gitleaks_result(raw_finding))
            except ValueError:
                continue
        return findings

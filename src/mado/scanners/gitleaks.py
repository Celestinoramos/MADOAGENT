"""Gitleaks scanner adapter (secret detection)."""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mado.findings.schema import Finding, normalize_gitleaks_result
from mado.scanners.base import resolve_binary


def gitleaks_records(payload: Any) -> list[dict[str, Any]]:
    """Extract leak objects from a Gitleaks JSON report.

    Official ``--report-format json`` writes a list of findings. Some wrappers
    nest the same objects under ``Findings`` / ``findings``.
    """
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        nested = payload.get("Findings", payload.get("findings"))
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]
    return []


@dataclass(slots=True)
class GitleaksScanner:
    """Run Gitleaks and normalize its JSON report."""

    name: str = "gitleaks"

    @classmethod
    def is_available(cls) -> bool:
        return resolve_binary("gitleaks") is not None

    def run(self, path: str) -> list[Finding]:
        executable = resolve_binary("gitleaks")
        if executable is None:
            raise RuntimeError("Gitleaks binary not found. Install gitleaks and ensure it is on PATH.")

        target = Path(path).resolve()
        if target.is_file():
            target = target.parent

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as report_file:
            report_path = report_file.name

        command = [
            executable,
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

        try:
            raw_text = Path(report_path).read_text(encoding="utf-8").strip()
            payload: Any = json.loads(raw_text) if raw_text else []
        except (json.JSONDecodeError, OSError):
            payload = []
        finally:
            Path(report_path).unlink(missing_ok=True)

        findings: list[Finding] = []
        for raw_finding in gitleaks_records(payload):
            try:
                findings.append(normalize_gitleaks_result(raw_finding))
            except ValueError:
                continue
        return findings

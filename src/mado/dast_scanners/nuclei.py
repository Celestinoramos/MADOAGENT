"""Nuclei dynamic scanner adapter.

Runs the Nuclei binary against a running application in JSONL output mode and
normalizes each match into a finding.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

from mado.dast_scanners.base import binary_available
from mado.findings.schema import Finding, normalize_nuclei_result


@dataclass(slots=True)
class NucleiScanner:
    """Run ``nuclei`` and normalize its JSONL output."""

    name: str = "nuclei"

    @classmethod
    def is_available(cls) -> bool:
        return binary_available("nuclei")

    def run(self, url: str) -> list[Finding]:
        if not self.is_available():
            raise RuntimeError("Nuclei binary not found. Install nuclei (go install) and ensure it is on PATH.")

        command = ["nuclei", "-u", url, "-jsonl", "-silent"]
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode not in (0, 1):
            details = completed.stderr.strip() or completed.stdout.strip() or "nuclei exited with an unexpected error"
            raise RuntimeError(f"Nuclei execution failed (exit code {completed.returncode}): {details}")

        findings: list[Finding] = []
        for line in completed.stdout.splitlines():
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(raw, dict):
                continue
            try:
                findings.append(normalize_nuclei_result(raw))
            except ValueError:
                continue
        return findings

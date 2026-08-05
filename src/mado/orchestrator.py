"""Scan orchestration for the MVP phase."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from mado.findings.schema import Finding
from mado.scanners.base import Scanner
from mado.scanners.semgrep import SemgrepScanner


@dataclass(slots=True)
class Orchestrator:
    """Coordinate scanners for a scan run.

    In phase 1 the orchestrator is intentionally small: it always runs Semgrep
    and returns normalized findings. Later phases can expand this to stack
    detection, diff scope, and additional scanners without changing the CLI.
    """

    scanners: list[Scanner] = field(default_factory=lambda: [SemgrepScanner()])

    def run(self, path: str) -> list[Finding]:
        """Run all configured scanners for the given path."""

        findings: list[Finding] = []
        for scanner in self.scanners:
            findings.extend(scanner.run(path))
        return findings


def run_orchestrator(path: str, scanners: Iterable[Scanner] | None = None) -> list[Finding]:
    """Convenience wrapper used by the CLI and tests."""

    configured_scanners = list(scanners) if scanners is not None else [SemgrepScanner()]
    orchestrator = Orchestrator(configured_scanners)
    return orchestrator.run(path)

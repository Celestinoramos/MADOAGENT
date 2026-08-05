"""Common scanner interface."""

from __future__ import annotations

from typing import Protocol

from mado.findings.schema import Finding


class Scanner(Protocol):
    """Scanner adapter interface used by the orchestrator."""

    name: str

    def run(self, path: str) -> list[Finding]:
        """Run the scanner against a path and return normalized findings."""

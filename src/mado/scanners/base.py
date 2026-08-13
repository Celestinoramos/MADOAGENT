"""Common scanner interface and helpers."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Protocol

from mado.findings.schema import Finding


class Scanner(Protocol):
    """Scanner adapter interface used by the orchestrator."""

    name: str

    @classmethod
    def is_available(cls) -> bool:
        """Return True when the underlying tool is installed."""

    def run(self, path: str) -> list[Finding]:
        """Run the scanner against a path and return normalized findings."""


def binary_available(binary: str) -> bool:
    """Return True when the scanner binary is reachable on PATH."""
    return shutil.which(binary) is not None


def resolve_target_path(path: str) -> Path:
    """Return the resolved path, using the parent when given a file."""
    resolved = Path(path).resolve()
    if resolved.is_file():
        return resolved.parent
    return resolved

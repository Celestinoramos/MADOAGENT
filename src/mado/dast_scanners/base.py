"""Common DAST scanner interface."""

from __future__ import annotations

import shutil
from typing import Protocol

from mado.findings.schema import Finding


class DastScanner(Protocol):
    """Dynamic scanning adapter interface (ZAP, Nuclei)."""

    name: str

    def run(self, url: str) -> list[Finding]:
        """Run the scanner against a URL and return normalized findings."""


def binary_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def docker_available() -> bool:
    return shutil.which("docker") is not None

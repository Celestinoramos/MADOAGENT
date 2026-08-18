"""Common scanner interface and helpers."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Protocol

from mado.findings.schema import Finding

_logger = logging.getLogger(__name__)


class Scanner(Protocol):
    """Scanner adapter interface used by the orchestrator."""

    name: str

    @classmethod
    def is_available(cls) -> bool:
        """Return True when the underlying tool is installed."""

    def run(self, path: str) -> list[Finding]:
        """Run the scanner against a path and return normalized findings."""


class BaseScanner:
    """Base class for scanner implementations with standardized error handling.

    Provides a consistent pattern for handling scanner errors, logging, and
    returning empty finding lists instead of propagating exceptions.
    """

    def scan(self, path: str) -> list[Finding]:
        """Run the scanner against a path and return normalized findings.

        Subclasses should implement the core scanning logic in ``_do_scan()``
        and this method will handle errors gracefully.
        """
        try:
            return self._do_scan(path)
        except ValueError as e:
            _logger.warning("ValueError in %s scanner for %s: %s", self.name, path, e)
            return []
        except Exception as e:
            _logger.error("Unexpected error in %s scanner for %s: %s", self.name, path, e, exc_info=True)
            return []

    def _do_scan(self, path: str) -> list[Finding]:
        """Core scanning logic to be implemented by subclasses."""
        raise NotImplementedError


def binary_available(binary: str) -> bool:
    """Return True when the scanner binary is reachable on PATH."""
    return shutil.which(binary) is not None


def project_venv_dir() -> Path:
    """Return the project's ``.venv`` directory, when it exists."""
    return Path(__file__).resolve().parents[3] / ".venv"


def resolve_binary(name: str) -> str | None:
    """Resolve a scanner binary: project venv first, then PATH.

    This mirrors Semgrep's resolver so scanners installed in the project's
    own virtualenv are found even when Madó itself runs from another Python
    environment (e.g. an editable system install).
    """
    venv_binary = project_venv_dir() / "bin" / name
    if venv_binary.exists():
        return str(venv_binary)
    return shutil.which(name)


def resolve_target_path(path: str) -> Path:
    """Return the resolved path, using the parent when given a file."""
    resolved = Path(path).resolve()
    if resolved.is_file():
        return resolved.parent
    return resolved

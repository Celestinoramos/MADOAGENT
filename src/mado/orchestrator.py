"""Scan orchestration for the MVP phase."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable
import subprocess
from pathlib import Path

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


def _git_changed_files(path: str) -> list[str]:
    """Return a list of files changed according to `git diff --name-only`.

    If the path is not a git repository or Git is not available, an empty
    list is returned so the caller can fall back to scanning the whole tree.
    """

    repo = Path(path).resolve()
    if repo.is_file():
        repo = repo.parent

    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), "diff", "--name-only"], capture_output=True, text=True
        )
    except FileNotFoundError:
        return []

    if completed.returncode != 0:
        return []

    files = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    return files


def run_orchestrator(path: str, scanners: Iterable[Scanner] | None = None, diff: bool = False) -> list[Finding]:
    """Convenience wrapper used by the CLI and tests.

    If `diff` is true, attempt to limit the scan to files reported by Git.
    If Git is unavailable or the repository cannot be inspected, the full
    path is scanned instead.
    """

    configured_scanners = list(scanners) if scanners is not None else [SemgrepScanner()]
    orchestrator = Orchestrator(configured_scanners)

    if diff:
        changed = _git_changed_files(path)
        if changed:
            # If git returned changed files, run scanners against each file
            findings: list[Finding] = []
            for scanner in orchestrator.scanners:
                for file_path in changed:
                    findings.extend(scanner.run(file_path))
            return findings
        # fallthrough: no git info available — scan whole path

    return orchestrator.run(path)

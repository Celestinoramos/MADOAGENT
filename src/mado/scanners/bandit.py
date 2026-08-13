"""Bandit scanner adapter (Python SAST)."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from mado.findings.schema import Finding, normalize_bandit_result
from mado.scanners.base import resolve_binary


@dataclass(slots=True)
class BanditScanner:
    """Run Bandit and normalize its JSON output."""

    name: str = "bandit"
    exclude: tuple[str, ...] = ()

    @classmethod
    def is_available(cls) -> bool:
        return resolve_binary("bandit") is not None

    def run(self, path: str) -> list[Finding]:
        executable = resolve_binary("bandit")
        if executable is None:
            raise RuntimeError("Bandit binary not found. Install bandit and ensure it is on PATH.")

        target = Path(path).resolve()
        if target.is_file() and target.suffix != ".py":
            return []

        command = [executable, "-r", "-f", "json", "-q"]
        if target.is_file():
            command = [executable, "-f", "json", "-q"]
        else:
            command.append("--exclude")
            command.append(",".join(self.exclude))
        command.append(str(target))

        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode not in (0, 1):
            details = completed.stderr.strip() or completed.stdout.strip() or "bandit exited with an unexpected error"
            raise RuntimeError(f"Bandit execution failed (exit code {completed.returncode}): {details}")

        try:
            payload: dict = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Bandit returned invalid JSON output") from exc

        findings: list[Finding] = []
        for raw_result in payload.get("results", []):
            if not isinstance(raw_result, dict):
                continue
            try:
                findings.append(normalize_bandit_result(raw_result))
            except ValueError:
                continue
        return findings

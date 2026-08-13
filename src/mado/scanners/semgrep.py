"""Semgrep scanner adapter."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mado.findings.schema import Finding, normalize_semgrep_result


@dataclass(slots=True)
class SemgrepScanner:
    """Run Semgrep and normalize its JSON output."""

    name: str = "semgrep"
    exclude: tuple[str, ...] = ()

    @classmethod
    def is_available(cls) -> bool:
        try:
            cls()._resolve_executable()
        except FileNotFoundError:
            return False
        return True

    def _resolve_config_path(self) -> str:
        config_path = Path(__file__).with_name("rules") / "semgrep.yml"
        if not config_path.exists():
            raise FileNotFoundError(f"Semgrep config file not found: {config_path}")
        return str(config_path)

    def _resolve_excludes(self, target_path: str) -> list[str]:
        config_path = Path(self._resolve_config_path()).resolve()
        target_root = Path(target_path).resolve()

        if target_root.is_file():
            target_root = target_root.parent

        if config_path.is_relative_to(target_root):
            return [str(config_path.relative_to(target_root))]

        return []

    def _resolve_executable(self) -> list[str]:
        project_root = Path(__file__).resolve().parents[3]
        project_venv_executable = project_root / ".venv" / "bin" / "semgrep"
        if project_venv_executable.exists():
            return [str(project_venv_executable)]

        executable = shutil.which("semgrep")
        if executable:
            return [executable]

        venv_executable = Path(sys.executable).with_name("semgrep")
        if venv_executable.exists():
            return [str(venv_executable)]

        if importlib.util.find_spec("semgrep") is not None:
            return [sys.executable, "-m", "semgrep"]

        raise FileNotFoundError("semgrep executable not found in PATH or the active Python environment")

    def run(self, path: str) -> list[Finding]:
        try:
            command = self._resolve_executable() + ["--json", "--config", self._resolve_config_path()]
        except FileNotFoundError as exc:
            raise RuntimeError("Semgrep binary not found. Install semgrep and ensure it is on PATH.") from exc

        for exclude in self._resolve_excludes(path):
            command.extend(["--exclude", exclude])
        for pattern in self.exclude:
            command.extend(["--exclude", pattern])
        command.append(path)
        try:
            completed = subprocess.run(command, capture_output=True, text=True)
        except FileNotFoundError as exc:
            raise RuntimeError("Semgrep binary not found. Install semgrep and ensure it is on PATH.") from exc

        if completed.returncode not in (0, 1):
            stderr = completed.stderr.strip()
            stdout = completed.stdout.strip()
            details = stderr or stdout or "semgrep exited with an unexpected error"
            raise RuntimeError(f"Semgrep execution failed (exit code {completed.returncode}): {details}")

        try:
            payload: dict[str, Any] = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Semgrep returned invalid JSON output") from exc

        results = payload.get("results", [])
        if not isinstance(results, list):
            raise RuntimeError("Semgrep JSON payload does not contain a results list")

        findings: list[Finding] = []
        for raw_result in results:
            if not isinstance(raw_result, dict):
                continue
            findings.append(normalize_semgrep_result(raw_result))
        for finding in findings:
            self._fill_code_snippet(finding)
        return findings

    @staticmethod
    def _fill_code_snippet(finding: Finding) -> None:
        """Prefer the real code line from disk over the report snippet."""
        if not finding.line:
            return
        try:
            lines = Path(finding.file).read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        if 1 <= finding.line <= len(lines):
            finding.code_snippet = lines[finding.line - 1]

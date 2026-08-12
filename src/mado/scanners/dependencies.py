"""Dependency vulnerability scanners (pip-audit / npm audit)."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from mado.findings.schema import (
    Finding,
    normalize_npm_vuln,
    normalize_pip_audit_vuln,
)

_PYTHON_MANIFESTS = ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py")
_NODE_MANIFESTS = ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")


def _find_manifest(target_root: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = target_root / name
        if candidate.exists():
            return candidate
    return None


@dataclass(slots=True)
class PipAuditScanner:
    """Scan Python dependencies with pip-audit."""

    name: str = "pip-audit"

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("pip-audit") is not None

    def run(self, path: str) -> list[Finding]:
        if not self.is_available():
            raise RuntimeError("pip-audit binary not found. Install pip-audit and ensure it is on PATH.")

        target = Path(path).resolve()
        if target.is_file():
            target = target.parent
        manifest = _find_manifest(target, _PYTHON_MANIFESTS)
        if manifest is None:
            return []

        command = ["pip-audit", "-f", "json"]
        if manifest.name in ("requirements.txt", "Pipfile"):
            command += ["-r", str(manifest)]
        else:
            command.append(str(target))

        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode not in (0, 1, 2, 3):
            details = completed.stderr.strip() or completed.stdout.strip() or "pip-audit exited with an unexpected error"
            raise RuntimeError(f"pip-audit execution failed (exit code {completed.returncode}): {details}")

        try:
            payload: dict = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("pip-audit returned invalid JSON output") from exc

        findings: list[Finding] = []
        for dependency in payload.get("dependencies", []):
            if not isinstance(dependency, dict):
                continue
            for vuln in dependency.get("vulns", []):
                if not isinstance(vuln, dict):
                    continue
                findings.append(normalize_pip_audit_vuln(dependency, vuln, str(manifest)))
        return findings


@dataclass(slots=True)
class NpmAuditScanner:
    """Scan Node.js dependencies with npm audit."""

    name: str = "npm-audit"

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which("npm") is not None

    def run(self, path: str) -> list[Finding]:
        if shutil.which("npm") is None:
            raise RuntimeError("npm binary not found. Install Node.js and ensure npm is on PATH.")

        target = Path(path).resolve()
        if target.is_file():
            target = target.parent
        manifest = _find_manifest(target, _NODE_MANIFESTS)
        if manifest is None:
            return []

        completed = subprocess.run(
            ["npm", "audit", "--json"], cwd=str(target), capture_output=True, text=True
        )
        if completed.returncode not in (0, 1):
            details = completed.stderr.strip() or completed.stdout.strip() or "npm audit exited with an unexpected error"
            raise RuntimeError(f"npm audit execution failed (exit code {completed.returncode}): {details}")

        try:
            payload: dict = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("npm audit returned invalid JSON output") from exc

        vulnerabilities = payload.get("vulnerabilities", {})
        if not isinstance(vulnerabilities, dict):
            return []

        findings: list[Finding] = []
        manifest_name = manifest.name
        for package, info in vulnerabilities.items():
            if not isinstance(info, dict):
                continue
            findings.append(normalize_npm_vuln(package, info, str(target / manifest_name)))
        return findings


class DependencyScanner:
    """Dispatch to the right dependency scanner based on the detected stack."""

    @staticmethod
    def for_stack(stacks: set[str]) -> list[object]:
        scanners: list[object] = []
        if "python" in stacks:
            scanners.append(PipAuditScanner())
        if "node" in stacks:
            scanners.append(NpmAuditScanner())
        return scanners

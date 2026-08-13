"""Stack detection and scanner selection."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from mado.scanners.bandit import BanditScanner
from mado.scanners.base import Scanner
from mado.scanners.dependencies import DependencyScanner, NpmAuditScanner, PipAuditScanner
from mado.scanners.gitleaks import GitleaksScanner
from mado.scanners.semgrep import SemgrepScanner

_STACK_INDICATORS: dict[str, tuple[str, ...]] = {
    "python": ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "setup.cfg"),
    "node": ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
    "go": ("go.mod",),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "ruby": ("Gemfile", "Gemfile.lock"),
    "php": ("composer.json",),
}

_SAST_SCANNERS: dict[str, list[Callable[..., Scanner]]] = {
    "python": [SemgrepScanner, BanditScanner],
    "node": [SemgrepScanner],
    "go": [SemgrepScanner],
    "java": [SemgrepScanner],
    "ruby": [SemgrepScanner],
    "php": [SemgrepScanner],
}


def detect_stack(files: Iterable[str]) -> set[str]:
    """Return the set of stacks detected from the given files."""
    stacks: set[str] = set()
    for file_path in files:
        name = Path(file_path).name
        for stack, indicators in _STACK_INDICATORS.items():
            if name in indicators:
                stacks.add(stack)
    return stacks


def _indicator_files(target_root: Path) -> list[str]:
    if target_root.is_file():
        return [target_root.name]
    if not target_root.is_dir():
        return []
    names: list[str] = []
    for indicators in _STACK_INDICATORS.values():
        for indicator in indicators:
            if (target_root / indicator).exists():
                names.append(indicator)
                break
    return names


def detect_stack_for_path(path: str) -> set[str]:
    """Detect the stack for a scan target directory or file."""
    root = Path(path).resolve()
    return detect_stack(_indicator_files(root))


def _scanner_excludes(config: Any | None) -> tuple[str, ...]:
    """Derive scanner-level excludes from the config ignore paths.

    Only safe relative patterns are forwarded to the underlying tools:
    absolute paths, parent traversal and home references are skipped.
    """
    if config is None:
        return ()
    excludes: list[str] = []
    for entry in config.ignore_paths:
        cleaned = str(entry).strip().rstrip("/")
        if not cleaned or cleaned.startswith(("/", "~", "..")):
            continue
        excludes.append(cleaned)
    return tuple(excludes)


def select_scanners(path: str, stacks: set[str], config: Any | None = None) -> list[Scanner]:
    """Choose the active scanners for the detected stack.

    A scanner is included when it applies to the stack (or is universal), is
    enabled in the configuration (when provided), and its binary is available.
    """

    root = Path(path).resolve()
    if root.is_file():
        root = root.parent

    enable_semgrep = bool(config and config.get_scanner_enabled("semgrep")) if config else True
    excludes = _scanner_excludes(config)
    enabled: list[Scanner] = []
    if enable_semgrep and SemgrepScanner.is_available():
        enabled.append(SemgrepScanner(exclude=excludes))

    if GitleaksScanner.is_available():
        enabled.append(GitleaksScanner())

    for stack in sorted(stacks):
        for scanner_cls in _SAST_SCANNERS.get(stack, []):
            if scanner_cls is SemgrepScanner:
                continue
            scanner = scanner_cls(exclude=excludes)
            if scanner.is_available():
                enabled.append(scanner)

    dependency_scanners = DependencyScanner.for_stack(stacks)
    enabled.extend(scanner for scanner in dependency_scanners if scanner.is_available())
    return enabled


def missing_scanners_for_stack(stacks: set[str]) -> list[str]:
    """Names of scanners that would apply to the stack but are not installed."""
    missing: list[str] = []
    if "python" in stacks:
        if not BanditScanner.is_available():
            missing.append("bandit")
        if not PipAuditScanner.is_available():
            missing.append("pip-audit")
    if "node" in stacks:
        if not NpmAuditScanner.is_available():
            missing.append("npm")
    return missing

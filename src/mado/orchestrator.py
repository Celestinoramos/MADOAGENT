"""Scan orchestration for the static (code) mode."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from mado.config import Config, load_config
from mado.env import load_project_env
from mado.explanations import explain_finding
from mado.findings.cache import ExplanationCache
from mado.findings.ignore import IgnoreList
from mado.findings.schema import Finding, meets_severity_threshold, normalize_severity
from mado.llm.client import set_llm_enabled, set_llm_model
from mado.scanners.base import Scanner
from mado.scanners.registry import (
    detect_stack,
    detect_stack_for_path,
    missing_scanners_for_stack,
    select_scanners,
)

_REPO_SCOPED_SCANNERS = {"gitleaks", "pip-audit", "npm-audit"}

# Findings from these scanners stay regardless of file extension: secrets can
# live in any file (configs, .env, docs) and dependency findings target
# manifests such as requirements.txt or package-lock.json.
_CODE_FILTER_EXEMPT = _REPO_SCOPED_SCANNERS


@dataclass(slots=True)
class ScanResult:
    """Outcome of a static scan run."""

    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stacks: set[str] = field(default_factory=set)
    config: Config = field(default_factory=Config)


def _git_changed_files(path: str) -> list[str]:
    """Return absolute paths changed since the last commit.

    If the path is not a Git repository or Git is unavailable, an empty list
    is returned so the caller can fall back to scanning the whole tree.
    """

    repo = Path(path).resolve()
    if repo.is_file():
        repo = repo.parent

    try:
        completed = subprocess.run(["git", "-C", str(repo), "diff", "--name-only"], capture_output=True, text=True)
    except FileNotFoundError:
        return []

    if completed.returncode != 0:
        return []

    return [str((repo / line.strip()).resolve()) for line in completed.stdout.splitlines() if line.strip()]


def _matches_ignore(file_path: str, scan_root: Path, ignore_paths: list[str]) -> bool:
    """Return True when a finding's file matches one of the ignored paths."""
    if not ignore_paths:
        return False
    try:
        relative = os.path.relpath(Path(file_path).resolve(), scan_root)
    except ValueError:
        relative = file_path
    normalized = relative.replace("\\", "/")
    for ignored in ignore_paths:
        pattern = ignored.strip().replace("\\", "/").rstrip("/")
        if not pattern:
            continue
        if normalized == pattern or normalized.startswith(pattern + "/"):
            return True
        if Path(ignored).name in normalized.split("/"):
            continue
    return False


def _filter_non_code(findings: list[Finding], code_extensions: list[str]) -> list[Finding]:
    """Drop SAST findings reported in non-code files (docs, images, ...).

    An empty extension list disables the filter. Scanners in
    :data:`_CODE_FILTER_EXEMPT` (secrets and dependency scanners) are never
    filtered.
    """
    if not code_extensions:
        return findings
    allowed = {f".{extension.lstrip('.').lower()}" for extension in code_extensions}
    return [
        finding
        for finding in findings
        if finding.scanner in _CODE_FILTER_EXEMPT or Path(finding.file).suffix.lower() in allowed
    ]


def _filter_and_enrich(
    findings: list[Finding],
    config: Config,
    scan_root: Path,
    cache: ExplanationCache,
    ignore: IgnoreList | None = None,
) -> list[Finding]:
    ignored = ignore if ignore is not None else IgnoreList(root=scan_root)
    kept: list[Finding] = []
    for finding in findings:
        if ignored.contains(finding.id):
            continue
        if _matches_ignore(finding.file, scan_root, config.ignore_paths):
            continue
        if not meets_severity_threshold(normalize_severity(finding.severity_raw), config.severity_threshold):
            continue
        if finding.explanation is None:
            finding.explanation = explain_finding(finding, cache=cache)
        kept.append(finding)
    return kept


def run_scan(
    path: str,
    diff: bool = False,
    config: Config | None = None,
    scanners: Iterable[Scanner] | None = None,
) -> ScanResult:
    """Run the full static scan pipeline for a project path.

    Steps: resolve scope (full tree or ``git diff``), detect the stack, select
    the applicable and available scanners, run them, normalize + filter the
    findings, and enrich each one through the RAG + LLM pipeline (with cache).
    """

    active_config = config if config is not None else load_config(path)
    load_project_env(path)
    set_llm_enabled(active_config.llm_enabled)
    set_llm_model(active_config.llm.get("model"))

    scan_root = Path(path).resolve()
    if scan_root.is_file():
        scan_root = scan_root.parent

    warnings: list[str] = []
    changed: list[str] = []
    if diff:
        changed = _git_changed_files(path)

    stacks = detect_stack_for_path(path)
    stacks.update(detect_stack(changed))
    stacks = {stack for stack in stacks if stack}

    missing = missing_scanners_for_stack(stacks)
    if missing:
        warnings.append(
            "Scanners not installed (skipped): "
            + ", ".join(sorted(missing))
            + " — install them to enable those checks."
        )

    selected = list(scanners) if scanners is not None else select_scanners(path, stacks, active_config)
    if not selected:
        warnings.append("No scanners available. Install semgrep to run static checks.")

    findings: list[Finding] = []
    for scanner in selected:
        try:
            if diff and changed and scanner.name not in _REPO_SCOPED_SCANNERS:
                for file_path in changed:
                    findings.extend(scanner.run(file_path))
            else:
                findings.extend(scanner.run(path))
        except (RuntimeError, ValueError) as exc:
            warnings.append(f"[{scanner.name}] {exc}")
        except FileNotFoundError as exc:
            warnings.append(f"[{scanner.name}] {exc}")

    cache = ExplanationCache(root=scan_root, ttl_days=active_config.cache_ttl_days)
    findings = _filter_non_code(findings, active_config.code_extensions)
    findings = _filter_and_enrich(findings, active_config, scan_root, cache)

    return ScanResult(findings=findings, warnings=warnings, stacks=stacks, config=active_config)


def run_orchestrator(
    path: str,
    scanners: Iterable[Scanner] | None = None,
    diff: bool = False,
) -> list[Finding]:
    """Backwards-compatible wrapper returning only the findings list."""

    return run_scan(path, diff=diff, scanners=scanners).findings

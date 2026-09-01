"""Versioned persistence for the most recent scan report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mado.explanations.schema import FindingExplanation
from mado.findings.cache import cache_dir
from mado.findings.schema import Finding
from mado.report.models import Report

_STORE_VERSION = 1
_FILENAME = "last-scan.json"


class LastScanStore:
    """Read and write ``.mado/last-scan.json`` for a project."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.path = cache_dir(root) / _FILENAME

    def save(self, report: Report) -> None:
        payload = {"version": _STORE_VERSION, "report": report.to_dict()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(self.path)

    def load(self) -> Report | None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict) or payload.get("version") != _STORE_VERSION:
            return None
        raw_report = payload.get("report")
        if not isinstance(raw_report, dict):
            return None
        return _report_from_dict(raw_report)


def _report_from_dict(payload: dict[str, Any]) -> Report:
    findings = [_finding_from_dict(item) for item in payload.get("findings", []) if isinstance(item, dict)]
    return Report(
        target=str(payload.get("target", "")),
        summary={str(k): int(v) for k, v in payload.get("summary", {}).items()},
        findings=findings,
        generated_at=str(payload.get("generated_at", "")),
    )


def _finding_from_dict(payload: dict[str, Any]) -> Finding:
    raw_explanation = payload.get("explanation")
    explanation = FindingExplanation.from_dict(raw_explanation) if isinstance(raw_explanation, dict) else None
    extra = payload.get("extra")
    return Finding(
        id=str(payload.get("id", "")),
        file=str(payload.get("file", "")),
        line=payload.get("line") if isinstance(payload.get("line"), int) else None,
        scanner=str(payload.get("scanner", "")),
        rule_id=str(payload["rule_id"]) if payload.get("rule_id") is not None else None,
        cwe=str(payload["cwe"]) if payload.get("cwe") is not None else None,
        severity_raw=str(payload.get("severity_raw", payload.get("severity", "unknown"))),
        message_raw=str(payload.get("message", "")),
        code_snippet=str(payload["code_snippet"]) if payload.get("code_snippet") is not None else None,
        explanation=explanation,
        extra=extra if isinstance(extra, dict) else {},
    )

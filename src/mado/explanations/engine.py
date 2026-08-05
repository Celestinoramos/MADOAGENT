"""Deterministic explanation engine for normalized findings."""

from __future__ import annotations

from mado.findings.schema import Finding

from .knowledge_base import lookup_entry
from .schema import FindingExplanation


_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "ERROR": "high",
    "HIGH": "high",
    "WARNING": "medium",
    "MEDIUM": "medium",
    "INFO": "low",
    "LOW": "low",
}


def _normalize_severity(severity_raw: str) -> str:
    return _SEVERITY_MAP.get(severity_raw.strip().upper(), severity_raw.strip().lower() or "unknown")


def explain_finding(finding: Finding) -> FindingExplanation:
    """Produce a structured explanation for a finding using the local KB."""

    entry = lookup_entry(finding.cwe, finding.rule_id)
    return FindingExplanation(
        summary=entry.summary,
        root_cause=entry.root_cause,
        impact=entry.impact,
        severity=_normalize_severity(finding.severity_raw),
        remediation=entry.remediation,
        references=list(entry.references),
    )
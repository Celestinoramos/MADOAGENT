"""Explanation schema for scan findings."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class FindingExplanation:
    """Structured explanation for a normalized finding."""

    summary: str
    root_cause: str
    impact: str
    severity: str
    remediation: str
    references: list[str] = field(default_factory=list)
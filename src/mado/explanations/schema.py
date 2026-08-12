"""Explanation schema for scan findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class FindingExplanation:
    """Structured explanation for a normalized finding."""

    summary: str
    root_cause: str
    impact: str
    severity: str
    remediation: str
    references: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "FindingExplanation":
        """Build an explanation from a parsed LLM JSON payload (best-effort)."""
        references = payload.get("references")
        if isinstance(references, list):
            references = [str(ref) for ref in references]
        else:
            references = []
        return cls(
            summary=str(payload.get("summary", "")),
            root_cause=str(payload.get("root_cause", "")),
            impact=str(payload.get("impact", "")),
            severity=str(payload.get("severity", "unknown")),
            remediation=str(payload.get("remediation", "")),
            references=references,
        )
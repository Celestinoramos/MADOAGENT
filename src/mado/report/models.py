"""Report data model shared by renderers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from mado.findings.schema import Finding, normalize_severity, severity_rank

_SEVERITY_LABELS = ("critical", "high", "medium", "low", "unknown")


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Aggregate finding counts by normalized severity level."""
    counts = {label: 0 for label in _SEVERITY_LABELS}
    for finding in findings:
        counts[normalize_severity(finding.severity_raw)] += 1
    return counts


def highest_severity(findings: list[Finding]) -> str | None:
    """Return the most severe normalized level present, or None."""
    if not findings:
        return None
    ranked = [(severity_rank(normalize_severity(f.severity_raw)), f) for f in findings]
    return normalize_severity(max(ranked, key=lambda item: item[0])[1].severity_raw)


@dataclass(slots=True)
class Report:
    """Compiled report with an executive summary and normalized findings."""

    target: str
    summary: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @classmethod
    def from_findings(cls, target: str, findings: list[Finding]) -> Report:
        return cls(target=target, summary=severity_counts(findings), findings=list(findings))

    def to_dict(self) -> dict:
        from mado.explanations.engine import as_dict as explanation_as_dict

        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "summary": self.summary,
            "highest_severity": highest_severity(self.findings),
            "findings": [
                {
                    "id": finding.id,
                    "scanner": finding.scanner,
                    "severity": normalize_severity(finding.severity_raw),
                    "severity_raw": finding.severity_raw,
                    "file": finding.file,
                    "line": finding.line,
                    "rule_id": finding.rule_id,
                    "cwe": finding.cwe,
                    "message": finding.message_raw,
                    "code_snippet": finding.code_snippet,
                    "extra": finding.extra,
                    "explanation": (
                        explanation_as_dict(finding.explanation) if finding.explanation is not None else None
                    ),
                }
                for finding in self.findings
            ],
        }

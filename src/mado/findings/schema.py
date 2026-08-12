"""Finding schema and normalization helpers."""

from __future__ import annotations

from collections.abc import Iterable as IterableABC
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable
import hashlib

if TYPE_CHECKING:
    from mado.explanations.schema import FindingExplanation


@dataclass(slots=True)
class Finding:
    """Normalized security finding returned by scanners.

    The schema is aligned with the implementation document: every scanner
    output is converted into this shared shape before reaching the RAG/LLM
    pipeline. The optional ``explanation`` holds the enriched explanation
    produced after RAG + LLM processing.
    """

    id: str
    file: str
    line: int | None
    scanner: str
    rule_id: str | None
    cwe: str | None
    severity_raw: str
    message_raw: str
    code_snippet: str | None = None
    explanation: "FindingExplanation | None" = None
    extra: dict[str, Any] = field(default_factory=dict)


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _first_non_empty(values: Iterable[Any]) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _extract_cwe(metadata: Any) -> str | None:
    if isinstance(metadata, dict):
        cwe_value = metadata.get("cwe")
        if isinstance(cwe_value, str):
            return cwe_value.strip() or None
        if isinstance(cwe_value, IterableABC):
            return _first_non_empty(cwe_value)
    return None


def _hash_finding(file: str, line: int | None, scanner: str, rule_id: str | None, message_raw: str) -> str:
    payload = f"{file}:{line}:{scanner}:{rule_id}:{message_raw}".encode("utf-8")
    return "f_" + hashlib.sha1(payload).hexdigest()[:10]


def normalize_semgrep_result(result: dict[str, Any]) -> Finding:
    """Convert one Semgrep JSON result into the shared finding schema."""

    path = _first_non_empty([result.get("path"), result.get("extra", {}).get("path")])
    if not path:
        raise ValueError("Semgrep result is missing a file path")

    line = _as_int(result.get("start", {}).get("line"))
    extra = result.get("extra", {})
    message = _first_non_empty([extra.get("message"), result.get("message")])
    if not message:
        raise ValueError("Semgrep result is missing a message")

    rule_id = _first_non_empty([result.get("check_id"), extra.get("rule_id")])
    cwe = _extract_cwe(extra.get("metadata", {}))
    severity = _first_non_empty([extra.get("severity"), result.get("severity")]) or "UNKNOWN"
    code_snippet = None
    if isinstance(extra.get("lines"), str):
        code_snippet = extra.get("lines")
    elif isinstance(extra.get("line"), str):
        code_snippet = extra.get("line")

    finding_id = _hash_finding(path, line, "semgrep", rule_id, message)
    return Finding(
        id=finding_id,
        file=path,
        line=line,
        scanner="semgrep",
        rule_id=rule_id,
        cwe=cwe,
        severity_raw=severity,
        message_raw=message,
        code_snippet=code_snippet,
    )


_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}

_RAW_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "ERROR": "high",
    "HIGH": "high",
    "WARNING": "medium",
    "MEDIUM": "medium",
    "INFO": "low",
    "LOW": "low",
    "NONE": "unknown",
}


def normalize_severity(severity_raw: str) -> str:
    """Map a raw scanner severity into a normalized level."""
    cleaned = severity_raw.strip().upper()
    return _RAW_SEVERITY_MAP.get(cleaned, severity_raw.strip().lower() or "unknown")


def severity_rank(severity: str) -> int:
    """Return a numeric rank for comparing normalized severities."""
    return _SEVERITY_RANK.get(severity.strip().lower(), 0)


def meets_severity_threshold(severity: str, threshold: str) -> bool:
    """Return True when ``severity`` is at least as important as ``threshold``."""
    return severity_rank(severity) >= severity_rank(threshold)


def _make_finding(
    *,
    file: str,
    line: int | None,
    scanner: str,
    rule_id: str | None,
    cwe: str | None,
    severity_raw: str,
    message_raw: str,
    code_snippet: str | None = None,
    extra: dict[str, Any] | None = None,
) -> Finding:
    finding_id = _hash_finding(file, line, scanner, rule_id, message_raw)
    return Finding(
        id=finding_id,
        file=file,
        line=line,
        scanner=scanner,
        rule_id=rule_id,
        cwe=cwe,
        severity_raw=severity_raw,
        message_raw=message_raw,
        code_snippet=code_snippet,
        extra=extra or {},
    )


def _extract_bandit_cwe(issue_cwe: Any) -> str | None:
    if isinstance(issue_cwe, list):
        for item in issue_cwe:
            if isinstance(item, dict):
                cwe_value = item.get("id")
                if cwe_value:
                    return str(cwe_value)
    if isinstance(issue_cwe, dict):
        cwe_value = issue_cwe.get("id")
        if cwe_value:
            return str(cwe_value)
    return None


def normalize_bandit_result(result: dict[str, Any]) -> Finding:
    """Convert one Bandit JSON result into the shared finding schema."""
    path = _first_non_empty([result.get("filename")])
    if not path:
        raise ValueError("Bandit result is missing a file path")

    message = _first_non_empty([result.get("issue_text"), result.get("test_name")])
    if not message:
        raise ValueError("Bandit result is missing a message")

    code = result.get("code")
    snippet = None
    if isinstance(code, list):
        snippet = "\n".join(str(line) for line in code)
    elif isinstance(code, str):
        snippet = code

    return _make_finding(
        file=path,
        line=_as_int(result.get("line_number")),
        scanner="bandit",
        rule_id=result.get("test_id") or result.get("test_name"),
        cwe=_extract_bandit_cwe(result.get("issue_cwe")),
        severity_raw=result.get("issue_severity") or "UNKNOWN",
        message_raw=message,
        code_snippet=snippet,
        extra={"confidence": result.get("issue_confidence")},
    )


def normalize_gitleaks_result(result: dict[str, Any]) -> Finding:
    """Convert one Gitleaks finding into the shared schema."""
    path = _first_non_empty([result.get("File"), result.get("file")])
    if not path:
        raise ValueError("Gitleaks finding is missing a file path")

    secret = result.get("Secret")
    description = _first_non_empty([result.get("Description"), result.get("RuleID"), "Potential secret found"])
    severity = _first_non_empty([result.get("Severity"), result.get("severity")]) or "WARNING"

    snippet = None
    if isinstance(secret, str):
        snippet = secret if len(secret) < 200 else secret[:80] + "..." + secret[-20:]

    return _make_finding(
        file=path,
        line=_as_int(result.get("StartLine") or result.get("startLine")),
        scanner="gitleaks",
        rule_id=result.get("RuleID") or result.get("RuleId"),
        cwe="CWE-798",
        severity_raw=severity,
        message_raw=f"{description} (rule {result.get('RuleID')})" if result.get("RuleID") else description,
        code_snippet=snippet,
        extra={"match": result.get("Match")},
    )


def normalize_pip_audit_vuln(dependency: dict[str, Any], vuln: dict[str, Any], manifest: str) -> Finding:
    """Convert one pip-audit vulnerability into the shared schema."""
    package = dependency.get("name", "unknown")
    version = dependency.get("version", "?")
    vuln_id = vuln.get("id", "unknown")
    message = _first_non_empty([vuln.get("description")]) or f"{package} {version} has a known vulnerability"
    severity = _first_non_empty([vuln.get("severity")]) or "UNKNOWN"
    if isinstance(severity, dict):
        severity = _first_non_empty([severity.get("level"), severity.get("score")]) or "UNKNOWN"

    aliases = vuln.get("aliases") or []
    if isinstance(aliases, list):
        aliases = [str(alias) for alias in aliases]

    return _make_finding(
        file=manifest,
        line=None,
        scanner="pip-audit",
        rule_id=vuln_id,
        cwe="CWE-1104",
        severity_raw=str(severity).upper(),
        message_raw=f"{package}=={version} affected by {vuln_id}: {message}",
        code_snippet=f"{package}=={version}",
        extra={"fix_versions": vuln.get("fix_versions"), "aliases": aliases},
    )


def normalize_npm_vuln(package: str, info: dict[str, Any], manifest: str) -> Finding:
    """Convert one npm audit vulnerability into the shared schema."""
    severity = _first_non_empty([info.get("severity")]) or "UNKNOWN"

    via = info.get("via")
    title: str | None = None
    url: str | None = None
    cwe: str | None = "CWE-1104"
    if isinstance(via, list):
        for entry in via:
            if isinstance(entry, dict):
                title = _first_non_empty([entry.get("title"), entry.get("name")]) or title
                url = _first_non_empty([entry.get("url")]) or url
                if entry.get("cwe"):
                    cwe_value = entry["cwe"]
                    if isinstance(cwe_value, list) and cwe_value:
                        cwe = str(cwe_value[0])
                    elif isinstance(cwe_value, str):
                        cwe = cwe_value
                if title:
                    break

    message = title or info.get("range") or f"{package} has a known vulnerability"
    return _make_finding(
        file=manifest,
        line=None,
        scanner="npm-audit",
        rule_id=url or package,
        cwe=cwe,
        severity_raw=str(severity).upper(),
        message_raw=f"{package}: {message}",
        code_snippet=package,
        extra={"url": url, "range": info.get("range"), "direct": info.get("isDirect", False)},
    )


def normalize_zap_alert(alert: dict[str, Any]) -> Finding:
    """Convert one OWASP ZAP alert into the shared schema."""
    risk = _first_non_empty([alert.get("riskdesc"), alert.get("risk")]) or "informational"
    risk_word = risk.split(" ", 1)[0] if isinstance(risk, str) else risk

    cweid = alert.get("cweid")
    cwe = f"CWE-{cweid}" if cweid not in (None, 0, "0", "") else None
    url = _first_non_empty([alert.get("url"), alert.get("uri")]) or "unknown"
    alert_name = _first_non_empty([alert.get("alert"), alert.get("name")]) or "Unknown alert"
    detail = _first_non_empty([alert.get("desc"), alert.get("description")]) or alert_name

    return _make_finding(
        file=url,
        line=None,
        scanner="zap",
        rule_id=alert.get("wascid") and f"WASC-{alert.get('wascid')}",
        cwe=cwe,
        severity_raw=str(risk_word).upper(),
        message_raw=f"{alert_name}: {detail}",
        code_snippet=url,
        extra={"solution": alert.get("solution"), "evidence": alert.get("evidence")},
    )


def normalize_nuclei_result(result: dict[str, Any]) -> Finding:
    """Convert one Nuclei JSONL result into the shared schema."""
    info = result.get("info", {}) if isinstance(result.get("info"), dict) else {}
    matched = _first_non_empty([result.get("matched-at"), result.get("host")]) or "unknown"
    name = _first_non_empty([info.get("name")]) or result.get("template-id") or "Nuclei match"
    severity = _first_non_empty([info.get("severity")]) or "unknown"

    return _make_finding(
        file=matched,
        line=None,
        scanner="nuclei",
        rule_id=result.get("template-id"),
        cwe=None,
        severity_raw=str(severity).upper(),
        message_raw=name,
        code_snippet=matched,
        extra={
            "tags": info.get("tags"),
            "reference": info.get("reference"),
            "template": result.get("template-id"),
        },
    )

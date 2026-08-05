"""Finding schema and normalization helpers."""

from __future__ import annotations

from collections.abc import Iterable as IterableABC
from dataclasses import dataclass
from typing import Any, Iterable
import hashlib


@dataclass(slots=True)
class Finding:
    """Normalized security finding returned by scanners.

    The phase-1 MVP only needs the fields required to identify the issue and
    render it in the terminal, but the schema is already aligned with the
    implementation document so later phases can extend it without changing the
    public shape.
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

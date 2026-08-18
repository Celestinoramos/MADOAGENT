"""Small local knowledge base used to explain common findings."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class KnowledgeEntry:
    """Canonical guidance for a vulnerability family."""

    summary: str
    root_cause: str
    impact: str
    remediation: str
    references: tuple[str, ...]


_KB_BY_CWE: dict[str, KnowledgeEntry] = {
    "CWE-89": KnowledgeEntry(
        summary="SQL injection is caused by mixing untrusted input with SQL text.",
        root_cause="The query is assembled with attacker-controlled data instead of using parameters.",
        impact="An attacker can read, modify, or delete data by changing the SQL semantics.",
        remediation="Use parameterized queries or prepared statements and keep SQL text separate from user input.",
        references=(
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ),
    ),
    "CWE-78": KnowledgeEntry(
        summary="Command injection happens when shell commands include unsanitized input.",
        root_cause="Application data is passed into a shell command without strict validation or escaping.",
        impact="An attacker can execute arbitrary commands with the privileges of the process.",
        remediation=(
            "Avoid shell invocation when possible; otherwise pass arguments directly and validate input strictly."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/78.html",
            "https://owasp.org/www-community/attacks/Command_Injection",
        ),
    ),
    "CWE-798": KnowledgeEntry(
        summary="Hardcoded credentials make secret rotation and revocation unreliable.",
        root_cause="Sensitive values are stored in source code or config checked into the repository.",
        impact=(
            "Secrets can leak through source control, logs, or shared artifacts and are difficult to revoke quickly."
        ),
        remediation="Move secrets to environment variables or a secret manager and rotate exposed values.",
        references=(
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://owasp.org/www-project-top-ten/",
        ),
    ),
}

_KB_BY_KEYWORD: dict[str, KnowledgeEntry] = {
    "sql": _KB_BY_CWE["CWE-89"],
    "injection": _KB_BY_CWE["CWE-89"],
    "command": _KB_BY_CWE["CWE-78"],
    "shell": _KB_BY_CWE["CWE-78"],
    "secret": _KB_BY_CWE["CWE-798"],
    "credential": _KB_BY_CWE["CWE-798"],
    "password": _KB_BY_CWE["CWE-798"],
}


def _match_by_rule(rule_id: str | None) -> KnowledgeEntry | None:
    if not rule_id:
        return None

    lower_rule_id = rule_id.lower()
    for keyword, entry in _KB_BY_KEYWORD.items():
        if keyword in lower_rule_id:
            return entry
    return None


def expand_kb(additional_cwes: list[dict] | None = None) -> None:
    """Expand the local knowledge base with additional CWE entries.

    Accepts a list of dicts with keys: cwe_id, description, summary,
    root_cause, impact, remediation, references (tuple or list).
    Each entry is added to ``_KB_BY_CWE`` keyed by ``cwe_id``.
    """
    if additional_cwes is None:
        additional_cwes = []

    for entry in additional_cwes:
        cwe_id = entry.get("cwe_id", "").strip().upper()
        if not cwe_id or cwe_id in _KB_BY_CWE:
            continue
        kb_entry = KnowledgeEntry(
            summary=entry.get("summary", ""),
            root_cause=entry.get("root_cause", ""),
            impact=entry.get("impact", ""),
            remediation=entry.get("remediation", ""),
            references=tuple(entry.get("references", [])),
        )
        _KB_BY_CWE[cwe_id] = kb_entry


def lookup_entry(cwe: str | None, rule_id: str | None) -> KnowledgeEntry:
    """Return the best matching knowledge base entry for a finding."""

    if cwe:
        entry = _KB_BY_CWE.get(cwe.strip().upper())
        if entry is not None:
            return entry

    entry = _match_by_rule(rule_id)
    if entry is not None:
        return entry

    return KnowledgeEntry(
        summary=(
            "This finding matches a known security pattern, but the local knowledge base has no specific entry yet."
        ),
        root_cause="The scanner detected a rule that should be reviewed manually to confirm the true attack surface.",
        impact="Impact depends on the exact code path and the data flow that reaches the sink.",
        remediation=(
            "Review the code path, confirm whether user input reaches the sink, "
            "and apply the scanner's recommended fix."
        ),
        references=("https://owasp.org/www-project-top-ten/",),
    )

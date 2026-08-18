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


def expand_kb() -> None:
    """Expand the local knowledge base with additional CWE entries.

    This function can be called at initialization to populate the KB with
    more CWE entries beyond the bundled defaults.  The entries are added
    directly to ``_KB_BY_CWE`` and ``_KB_BY_KEYWORD`` so that subsequent
    ``lookup_entry`` calls find them immediately.
    """

    additional_cwes = [
        {
            "cwe_id": "CWE-20",
            "summary": "Improper input validation occurs when input is not validated before being used.",
            "root_cause": "The application does not validate or sanitize user input before processing.",
            "impact": "Attacker can send malicious data that alters the expected behavior of the application.",
            "remediation": "Validate all input against a whitelist of acceptable values; use type checking and length constraints.",
            "references": (
                "https://cwe.mitre.org/data/definitions/20.html",
                "https://owasp.org/www-community/attacks/Input_validation_cheat_sheet",
            ),
        },
        {
            "cwe_id": "CWE-352",
            "summary": "Cross-Site Request Forgery (CSRF) does not verify the intent of a request.",
            "root_cause": "The application does not verify that a request was intentionally initiated by the user.",
            "impact": "An attacker can forge authenticated requests that act on behalf of a victim user.",
            "remediation": "Use anti-CSRF tokens, SameSite cookie flags, and verify request origins.",
            "references": (
                "https://cwe.mitre.org/data/definitions/352.html",
                "https://owasp.org/www-community/attacks/csrf",
            ),
        },
        {
            "cwe_id": "CWE-79",
            "summary": "Cross-Site Scripting (XSS) does not sanitize untrusted output before including it in a web page.",
            "root_cause": "Untrusted data is included in a web page without proper escaping.",
            "impact": "Attacker can execute arbitrary JavaScript in the victim's browser, leading to session hijacking or defacement.",
            "remediation": "Escape all untrusted output based on the output context (HTML, JavaScript, CSS, URL).",
            "references": (
                "https://cwe.mitre.org/data/definitions/79.html",
                "https://owasp.org/www-community/xss-attacks",
            ),
        },
        {
            "cwe_id": "CWE-89",
        },
        {
            "cwe_id": "CWE-798",
        },
    ]

    for entry_data in additional_cwes:
        cwe_id = entry_data.get("cwe_id")
        if not cwe_id:
            continue

        # Skip if already exists
        if cwe_id in _KB_BY_CWE:
            continue

        entry = KnowledgeEntry(
            summary=entry_data.get("summary", ""),
            root_cause=entry_data.get("root_cause", ""),
            impact=entry_data.get("impact", ""),
            remediation=entry_data.get("remediation", ""),
            references=tuple(entry_data.get("references", ())),
        )
        _KB_BY_CWE[cwe_id] = entry

        # Also add keyword mappings for common lowercase lookups
        keyword = cwe_id.lower().replace("cwe-", "")
        _KB_BY_KEYWORD[keyword] = entry


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

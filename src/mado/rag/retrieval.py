"""Retrieval of security context for a finding."""

from __future__ import annotations

from mado.findings.schema import Finding
from mado.rag.ingest import build_default_store
from mado.rag.store import VectorStore

_store: VectorStore | None = None


def _get_store() -> VectorStore:
    global _store
    if _store is None or _store.is_empty():
        _store = build_default_store()
    return _store


def retrieve_context(finding: Finding, top_k: int = 3) -> list[str]:
    """Return the most relevant OWASP/CWE chunks for a finding.

    Uses multiple queries (CWE + rule_id, language + rule_id, severity + cwe)
    to improve retrieval coverage, then deduplicates results.

    The CWE-based query is always included first to ensure core relevance.
    """
    store = _get_store()
    # Always include the CWE-based query as the primary context
    primary_query = f"{finding.cwe} {finding.rule_id}"
    primary_hits = store.search(primary_query, top_k=top_k)

    # Collect additional queries for coverage expansion
    lang = getattr(finding, "language", "") or ""
    severity = getattr(finding, "severity_raw", "") or ""
    queries = [
        f"{lang} {finding.rule_id}",
        f"{severity} {finding.cwe}",
    ]
    all_hits: list[str] = [hit["text"] for hit in primary_hits]
    seen: set[str] = {hit["text"] for hit in primary_hits}

    for query in queries:
        hits = store.search(query, top_k=top_k)
        for hit in hits:
            hit_text = hit["text"]
            if hit_text not in seen:
                seen.add(hit_text)
                all_hits.append(hit_text)
    return all_hits[:top_k]


def build_query(cwe: str | None, rule_id: str | None) -> str:
    """Build the semantic retrieval query for a finding's keys."""
    return " ".join(part for part in (cwe, rule_id) if part)


def reset_store() -> None:
    """Drop the cached store (used by tests)."""
    global _store
    _store = None

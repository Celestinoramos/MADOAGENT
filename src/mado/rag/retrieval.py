"""Retrieval of security context for a finding."""

from __future__ import annotations

from mado.findings.schema import Finding
from mado.rag.ingest import build_default_store
from mado.rag.store import VectorStore

_store: VectorStore | None = None


def _get_store() -> VectorStore:
    global _store
    if _store is None or _store.is_empty:
        _store = build_default_store()
    return _store


def retrieve_context(finding: Finding, top_k: int = 3) -> list[str]:
    """Return the most relevant OWASP/CWE chunks for a finding.

    The query is built from the finding's semantic key (CWE id + rule id),
    falling back to the raw message when neither is present.
    """

    store = _get_store()
    parts = [part for part in (finding.cwe, finding.rule_id) if part]
    query = " ".join(parts) if parts else finding.message_raw
    hits = store.search(query, top_k=top_k)
    return [hit["text"] for hit in hits]


def build_query(cwe: str | None, rule_id: str | None) -> str:
    """Build the semantic retrieval query for a finding's keys."""
    return " ".join(part for part in (cwe, rule_id) if part)


def reset_store() -> None:
    """Drop the cached store (used by tests)."""
    global _store
    _store = None

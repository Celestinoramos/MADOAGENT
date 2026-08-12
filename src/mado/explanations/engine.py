"""Explanation engine combining RAG, LLM and a deterministic local KB.

The pipeline per finding is:

1. check the local explanation cache — on hit, reuse the stored payload;
2. retrieve security context from the RAG store (OWASP/CWE documents);
3. ask the LLM for a structured explanation when a backend is configured;
4. fall back to the deterministic local knowledge base when the LLM is not
   available or returns an unparsable response.

Every generated payload is written back to the cache.
"""

from __future__ import annotations

from dataclasses import asdict

from mado.findings.cache import ExplanationCache
from mado.findings.schema import Finding, normalize_severity
from mado.llm.client import LlmClient, llm_enabled
from mado.rag.retrieval import retrieve_context

from .knowledge_base import lookup_entry
from .schema import FindingExplanation

_TOP_K = 3


def explain_finding(
    finding: Finding,
    cache: ExplanationCache | None = None,
    root: str | None = None,
) -> FindingExplanation:
    """Produce a structured explanation for a finding.

    ``cache`` may be injected for tests; otherwise a cache rooted at ``root``
    (or the current working directory) is used.
    """

    active_cache = cache if cache is not None else ExplanationCache(root=root)

    cached = active_cache.get(finding)
    if cached:
        return FindingExplanation.from_dict(cached)

    payload = _generate_explanation_payload(finding)
    active_cache.set(finding, payload)
    active_cache.save()

    return FindingExplanation.from_dict(payload)


def _generate_explanation_payload(finding: Finding) -> dict:
    """Generate (and return) an explanation payload, preferring the LLM."""
    if llm_enabled():
        llm_payload = LlmClient().explain(finding, retrieved_context(finding, top_k=_TOP_K))
        if llm_payload is not None:
            if "severity" not in llm_payload or not llm_payload["severity"]:
                llm_payload["severity"] = normalize_severity(finding.severity_raw)
            return llm_payload

    entry = lookup_entry(finding.cwe, finding.rule_id)
    return {
        "summary": entry.summary,
        "root_cause": entry.root_cause,
        "impact": entry.impact,
        "severity": normalize_severity(finding.severity_raw),
        "remediation": entry.remediation,
        "references": list(entry.references),
    }


def as_dict(explanation: FindingExplanation) -> dict:
    """Serialize an explanation (references only when non-empty)."""
    payload = asdict(explanation)
    if not payload["references"]:
        payload.pop("references")
    return payload

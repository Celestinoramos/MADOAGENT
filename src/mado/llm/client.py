"""LLM client used to generate structured explanations for findings.

The client is lazy: if the Groq SDK is available and an API key is
configured (``GROQ_API_KEY``), it calls the model. Otherwise
:meth:`available` returns ``False`` and the caller should fall back to the
deterministic knowledge base. The env var ``MADO_LLM_PROVIDER`` can be set to
``"none"`` to force the fallback even when a key exists.
"""

from __future__ import annotations

import json
import os
from typing import Any

from mado.findings.schema import Finding
from mado.llm.prompts import SYSTEM_PROMPT, build_user_prompt
from mado.rag.retrieval import retrieve_context

_DEFAULT_MODEL = "mixtral-8x7b-32768"
_LLM_OVERRIDE: bool | None = None
_LLM_MODEL_OVERRIDE: str | None = None


def set_llm_enabled(value: bool | None) -> None:
    """Force the LLM backend on/off regardless of environment (config-driven)."""
    global _LLM_OVERRIDE
    _LLM_OVERRIDE = value


def set_llm_model(model: str | None) -> None:
    """Set the model configured in ``.mado.yml`` (``llm.model``) if any."""
    global _LLM_MODEL_OVERRIDE
    _LLM_MODEL_OVERRIDE = model if isinstance(model, str) and model else None


def llm_enabled() -> bool:
    """Return True when a real LLM backend is configured and usable."""
    if _LLM_OVERRIDE is False:
        return False
    if os.environ.get("MADO_LLM_PROVIDER", "").lower() == "none":
        return False
    if not os.environ.get("GROQ_API_KEY"):
        return False
    try:
        from groq import Groq  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return False
    return True


class LlmClient:
    """Thin wrapper around the Groq SDK that returns structured JSON."""

    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        self.model = model or _LLM_MODEL_OVERRIDE or _DEFAULT_MODEL
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self._client: Any | None = None

    def __repr__(self) -> str:
        masked = "***" if self.api_key else None
        return f"LlmClient(model={self.model!r}, api_key={masked!r})"

    @property
    def available(self) -> bool:
        return bool(self.api_key and llm_enabled())

    def _get_client(self) -> Any:
        if self._client is None:
            from groq import Groq

            self._client = Groq(api_key=self.api_key)
        return self._client

    def explain(self, finding: Finding, retrieved_context: list[str] | None = None) -> dict[str, Any] | None:
        """Ask the model for a structured explanation of a finding.

        Returns a dict matching the explanation schema, or ``None`` when the
        backend is not available or the response cannot be parsed.
        """

        if not self.available:
            return None

        context = retrieved_context if retrieved_context is not None else retrieve_context(finding)
        user_prompt = build_user_prompt(
            rule_id=finding.rule_id,
            cwe=finding.cwe,
            file=finding.file,
            line=finding.line,
            code_snippet=finding.code_snippet,
            retrieved_context=context,
        )

        try:
            response = self._get_client().chat.completions.create(
                model=self.model,
                max_tokens=1024,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except Exception:
            return None

        text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text")
        return self._parse_json(text)

    @staticmethod
    def _parse_json(text: str) -> dict[str, Any] | None:
        """Best-effort extraction of a JSON object from the model output."""
        text = text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:]
            text = text.strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start == -1 or end <= start:
                return None
            try:
                parsed = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
        if not isinstance(parsed, dict):
            return None
        return parsed


def enrich_with_llm(finding: Finding) -> dict[str, Any] | None:
    """Convenience: retrieve RAG context and call the LLM for one finding."""
    if not llm_enabled():
        return None
    client = LlmClient()
    return client.explain(finding)

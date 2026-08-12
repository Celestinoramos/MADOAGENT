from __future__ import annotations

import os
import unittest

from mado.llm.client import LlmClient, llm_enabled, set_llm_enabled
from mado.llm.prompts import SYSTEM_PROMPT, build_user_prompt


class LlmClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self._old_key = os.environ.get("ANTHROPIC_API_KEY")
        self._old_provider = os.environ.get("MADO_LLM_PROVIDER")
        set_llm_enabled(None)

    def tearDown(self) -> None:
        if self._old_key is None:
            os.environ.pop("ANTHROPIC_API_KEY", None)
        else:
            os.environ["ANTHROPIC_API_KEY"] = self._old_key
        if self._old_provider is None:
            os.environ.pop("MADO_LLM_PROVIDER", None)
        else:
            os.environ["MADO_LLM_PROVIDER"] = self._old_provider
        set_llm_enabled(None)

    def test_disabled_without_api_key(self) -> None:
        os.environ.pop("ANTHROPIC_API_KEY", None)
        self.assertFalse(llm_enabled())

    def test_override_can_force_disable(self) -> None:
        os.environ["ANTHROPIC_API_KEY"] = "test-key"
        set_llm_enabled(False)
        self.assertFalse(llm_enabled())

    def test_parse_json_with_markdown_fence(self) -> None:
        raw = '```json\n{"summary": "x", "severity": "high"}\n```'
        parsed = LlmClient._parse_json(raw)
        self.assertEqual(parsed["summary"], "x")

    def test_parse_json_with_surrounding_text(self) -> None:
        raw = 'Here you go:\n{"summary": "y"}\nDone.'
        parsed = LlmClient._parse_json(raw)
        self.assertEqual(parsed["summary"], "y")

    def test_parse_invalid_returns_none(self) -> None:
        self.assertIsNone(LlmClient._parse_json("not json at all"))

    def test_build_user_prompt_contains_keys(self) -> None:
        prompt = build_user_prompt(
            rule_id="python.sql.injection",
            cwe="CWE-89",
            file="src/app.py",
            line=10,
            code_snippet="query = f'SELECT * FROM users'",
            retrieved_context=["CWE-89 context"],
        )
        self.assertIn("CWE-89", prompt)
        self.assertIn("python.sql.injection", prompt)
        self.assertIn("CWE-89 context", prompt)
        self.assertIn("causa raiz", SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()

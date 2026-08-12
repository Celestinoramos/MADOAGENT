from __future__ import annotations

import unittest

from mado.findings.schema import Finding
from mado.rag.ingest import build_default_store, chunk_documents
from mado.rag.retrieval import reset_store, retrieve_context
from mado.rag.store import VectorStore


class VectorStoreTests(unittest.TestCase):
    def test_add_and_search(self) -> None:
        store = VectorStore()
        store.add([("a", "SQL injection is mixing user input into SQL queries"),
                   ("b", "hardcoded passwords and api keys are bad secrets"),
                   ("c", "the weather in lisbon is sunny today")])
        hits = store.search("sql injection query", top_k=1)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["id"], "a")

    def test_empty_store_returns_no_hits(self) -> None:
        store = VectorStore()
        self.assertEqual(store.search("anything"), [])
        self.assertTrue(store.is_empty)

    def test_save_and_load_roundtrip(self) -> None:
        import tempfile

        store = VectorStore()
        store.add([("k1", "first chunk about deserialization")])
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        store.save(path)
        loaded = VectorStore.load(path)
        self.assertEqual(len(loaded.chunks), 1)
        self.assertEqual(loaded.search("deserialization")[0]["id"], "k1")


class IngestionTests(unittest.TestCase):
    def test_bundled_docs_index(self) -> None:
        store = build_default_store()
        self.assertGreater(len(store.chunks), 5)
        hits = store.search("CWE-89 SQL injection parameterized", top_k=3)
        self.assertTrue(hits)

    def test_chunk_documents_split_by_heading(self) -> None:
        chunks = chunk_documents(["# A\n\n## CWE-89 — SQL Injection\n\nbody text\n\n## CWE-78 — OS Command Injection\n\nmore text\n"])
        keys = [key for key, _ in chunks]
        self.assertTrue(any("cwe-89" in key for key in keys))
        self.assertTrue(any("cwe-78" in key for key in keys))


class RetrievalTests(unittest.TestCase):
    def test_retrieve_context_for_cwe_89(self) -> None:
        reset_store()
        finding = Finding(
            id="x",
            file="src/app.py",
            line=1,
            scanner="semgrep",
            rule_id="python.sql.injection",
            cwe="CWE-89",
            severity_raw="ERROR",
            message_raw="SQL injection",
        )
        context = retrieve_context(finding)
        self.assertTrue(context)
        combined = " ".join(context).lower()
        self.assertIn("sql", combined)

    def test_retrieve_context_fallback_to_message(self) -> None:
        reset_store()
        finding = Finding(
            id="x",
            file="src/app.py",
            line=1,
            scanner="semgrep",
            rule_id=None,
            cwe=None,
            severity_raw="ERROR",
            message_raw="path traversal in file upload",
        )
        context = retrieve_context(finding)
        self.assertTrue(context)


if __name__ == "__main__":
    unittest.main()

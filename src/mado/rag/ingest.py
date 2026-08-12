"""Offline ingestion of OWASP/CWE documents into the local vector store.

The pipeline is: load the bundled markdown docs, split them into chunks, and
index each chunk in the :class:`~mado.rag.store.VectorStore`. Chunks are keyed
by the CWE id (or section header) so retrieval can later match findings by
their semantic key.
"""

from __future__ import annotations

import re
from pathlib import Path

from .store import VectorStore

_DATA_DIR = Path(__file__).parent / "data"


def _split_sections(markdown: str) -> list[tuple[str, str]]:
    """Split a markdown doc into (heading, body) sections."""
    sections: list[tuple[str, str]] = []
    current_heading = "general"
    body_parts: list[str] = []
    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()
        if line.startswith("## "):
            if body_parts:
                sections.append((current_heading, "\n".join(body_parts).strip()))
            current_heading = line[3:].strip()
            body_parts = []
        else:
            body_parts.append(line)
    if body_parts:
        sections.append((current_heading, "\n".join(body_parts).strip()))
    return sections


def _heading_key(heading: str) -> str:
    """Normalize a heading into a stable chunk id key."""
    return re.sub(r"[^a-z0-9]+", "-", heading.lower()).strip("-")


def chunk_documents(markdown_docs: list[str]) -> list[tuple[str, str]]:
    """Convert markdown documents into a flat list of ``(id, text)`` chunks."""
    chunks: list[tuple[str, str]] = []
    for doc_index, document in enumerate(markdown_docs):
        for heading, body in _split_sections(document):
            key = _heading_key(heading)
            chunk_id = f"doc{doc_index}-{key}"
            text = f"{heading}. {body}".strip()
            if text:
                chunks.append((chunk_id, text))
    return chunks


def load_default_documents() -> list[str]:
    """Read the bundled OWASP/CWE markdown documents."""
    docs: list[str] = []
    for path in sorted(_DATA_DIR.glob("*.md")):
        docs.append(path.read_text(encoding="utf-8"))
    return docs


def build_default_store() -> VectorStore:
    """Build and return a store indexed with the bundled documents."""
    store = VectorStore()
    store.add(chunk_documents(load_default_documents()))
    return store

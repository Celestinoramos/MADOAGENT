"""Lightweight local vector store for RAG retrieval.

The store keeps text chunks and a bag-of-words TF-IDF embedding so retrieval
works fully offline with no heavy dependencies. The public interface
(``add`` / ``search`` / ``save`` / ``load``) mirrors what a Chroma/FAISS
store would expose, so the backend can be swapped later without touching the
retrieval layer.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Iterable

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


def tokenize(text: str) -> list[str]:
    """Lowercase alphanumeric tokenization with char n-gram coverage."""
    tokens = _TOKEN_RE.findall(text.lower())
    ngrams: list[str] = []
    for token in tokens:
        ngrams.append(token)
        if len(token) >= 4:
            ngrams.extend(token[i : i + 3] for i in range(len(token) - 2))
    return ngrams


@dataclass(slots=True)
class _Chunk:
    id: str
    text: str
    tokens: list[str]


@dataclass(slots=True)
class VectorStore:
    """In-memory TF-IDF vector store with cosine-similarity search."""

    chunks: list[_Chunk] = field(default_factory=list)
    _doc_freq: dict[str, int] = field(default_factory=dict)

    def add(self, chunks: Iterable[tuple[str, str]]) -> None:
        """Add ``(id, text)`` pairs to the store."""
        new_chunks: list[_Chunk] = []
        for chunk_id, text in list(chunks):
            new_chunks.append(_Chunk(id=chunk_id, text=text, tokens=tokenize(text)))
        self.chunks.extend(new_chunks)

        unique: set[str] = set()
        for chunk in new_chunks:
            unique.clear()
            for token in chunk.tokens:
                if token not in unique:
                    self._doc_freq[token] = self._doc_freq.get(token, 0) + 1
                    unique.add(token)

    @property
    def is_empty(self) -> bool:
        return not self.chunks

    def _idf(self, token: str) -> float:
        total = len(self.chunks) or 1
        df = self._doc_freq.get(token, 0) or 1
        return math.log((1 + total) / (1 + df)) + 1.0

    def _embed(self, tokens: Iterable[str]) -> dict[str, float]:
        vector: dict[str, float] = {}
        for token in tokens:
            vector[token] = vector.get(token, 0.0) + 1.0
        for token, count in vector.items():
            vector[token] = count * self._idf(token)
        return vector

    @staticmethod
    def _cosine(left: dict[str, float], right: dict[str, float]) -> float:
        if not left or not right:
            return 0.0
        if len(left) > len(right):
            left, right = right, left
        dot = sum(weight * right.get(token, 0.0) for token, weight in left.items())
        norm_left = math.sqrt(sum(w * w for w in left.values()))
        norm_right = math.sqrt(sum(w * w for w in right.values()))
        if norm_left == 0.0 or norm_right == 0.0:
            return 0.0
        return dot / (norm_left * norm_right)

    def search(self, query: str, top_k: int = 3) -> list[dict[str, str]]:
        """Return the ``top_k`` most relevant chunks as ``{id, text}`` dicts."""
        query_tokens = tokenize(query)
        if not query_tokens or self.is_empty:
            return []
        query_vector = self._embed(query_tokens)

        ranked: list[tuple[float, _Chunk]] = []
        for chunk in self.chunks:
            score = self._cosine(query_vector, self._embed(chunk.tokens))
            if score > 0.0:
                ranked.append((score, chunk))
        ranked.sort(key=lambda item: item[0], reverse=True)

        return [{"id": chunk.id, "text": chunk.text} for _, chunk in ranked[:top_k]]

    def save(self, path: str) -> None:
        """Persist the store to a JSON file."""
        import json

        from pathlib import Path

        payload = {"chunks": [{"id": c.id, "text": c.text} for c in self.chunks]}
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, path: str) -> "VectorStore":
        """Load a store previously saved with :meth:`save`."""
        import json

        from pathlib import Path

        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        store = cls()
        store.add((chunk["id"], chunk["text"]) for chunk in payload["chunks"])
        return store

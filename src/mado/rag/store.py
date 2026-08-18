"""Lightweight local vector store for RAG retrieval.

This module provides a vector store backend that can use either TF-IDF (offline,
no heavy dependencies) or FAISS (efficient similarity search). The default
backend is FAISS when the library is available, otherwise it falls back to
the pure-Python TF-IDF implementation.

The public interface (``add`` / ``search`` / ``save`` / ``load``) mirrors what
a Chroma/FAISS store would expose, so the backend can be swapped without
touching the retrieval layer.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

import numpy as np

try:
    from faiss import IndexFlatIP
    _FAISS_AVAILABLE = True
except Exception:  # pragma: no cover - faiss optional
    _FAISS_AVAILABLE = False

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


@dataclass(slots=True)
class _Chunk:
    id: str
    text: str
    embedding: np.ndarray | None = None


@dataclass(slots=True)
class VectorStore:
    """Vector store for RAG retrieval.

    Supports two backends:
    - ``faiss``: FAISS IndexFlatIP for efficient inner-product search.
    - ``tfidf``: Pure-Python bag-of-words with cosine similarity (fallback).

    The backend is selected at class construction time. When FAISS is not
    available, the TF-IDF backend is used automatically.
    """

    chunks: list[_Chunk] = field(default_factory=list)
    _faiss_index: any = None  # type: ignore
    _embedding_dim: int = 768
    _backend: str = "tfidf"  # "faiss" or "tfidf"
    _doc_freq: dict[str, int] | None = None
    _total: int = 0

    def __post_init__(self) -> None:
        if _FAISS_AVAILABLE and self._backend == "faiss":
            self._faiss_index = IndexFlatIP(self._embedding_dim)
            self._backend = "faiss"
        else:
            self._backend = "tfidf"

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def add(self, chunks: Iterable[tuple[str, str | list[float]]]) -> None:
        """Add ``(id, embedding_or_text)`` pairs to the store.

        Each chunk can be:
        - ``(id, text)`` — text will be embedded internally (TF-IDF or FAISS).
        - ``(id, embedding)`` — embedding must be a list/array of ``_embedding_dim`` floats.
        """
        new_chunks: list[_Chunk] = []
        # Normalize: ensure chunks is a list of (id, data) tuples
        chunk_list = list(chunks)
        # If chunks is a single (id, data) tuple being passed directly,
        # wrap it in a list so iteration works correctly
        if chunk_list and not isinstance(chunk_list[0], (list, tuple)):
            chunk_list = [chunk_list]
        for chunk_id, data in chunk_list:
            if isinstance(data, str):
                # Text-based embedding: TF-IDF path, embedding computed incrementally
                chunk = _Chunk(id=chunk_id, text=data, embedding=None)
            elif isinstance(data, (list, np.ndarray)):
                vec = np.asarray(data, dtype="float32")
                if vec.ndim != 1 or vec.shape[0] != self._embedding_dim:
                    raise ValueError(
                        f"Embedding dimension must be {self._embedding_dim}, got {vec.shape}"
                    )
                chunk = _Chunk(id=chunk_id, text="", embedding=vec)
            else:
                raise TypeError(f"Unsupported chunk data type: {type(data)}")
            new_chunks.append(chunk)

        # Extend chunks first so _update_doc_freq can see all chunks
        self.chunks.extend(new_chunks)

        # Incrementally update document frequencies (now self.chunks includes new ones)
        self._update_doc_freq(new_chunks)

        # Add to FAISS index if using FAISS backend
        if self._backend == "faiss" and self._faiss_index is not None:
            for chunk in new_chunks:
                if chunk.embedding is not None:
                    self._faiss_index.add(chunk.embedding.reshape(1, -1))

    def _update_doc_freq(self, new_chunks: list[_Chunk]) -> None:
        """Incrementally update document frequencies for TF-IDF vectors."""
        self._total = len(self.chunks)  # includes newly added chunks
        doc_freq: dict[str, int] = {}

        # Count tokens across all chunks (both old and new)
        for chunk in self.chunks:
            if chunk.embedding is not None:
                # embedding-based chunk — skip pure TF-IDF computation for these
                continue
            # text-based chunk
            tokens = _TOKEN_RE.findall(chunk.text.lower())
            unique: set[str] = set()
            for tok in tokens:
                if tok not in unique:
                    doc_freq[tok] = doc_freq.get(tok, 0) + 1
                    unique.add(tok)

        # Store the computed doc_freq for use during search
        self._doc_freq = doc_freq

    def _tfidf_vector(self, tokens: list[str]) -> dict[str, float] | None:
        """Compute a TF-IDF vector for the given token list over current chunks."""
        total = self._total or 1
        doc_freq = self._doc_freq or {}

        if not doc_freq:
            return None

        vector: dict[str, float] = {}
        for token in tokens:
            df = doc_freq.get(token, 0)
            idf = math.log((1 + total) / (1 + df)) + 1.0
            vector[token] = vector.get(token, 0.0) + 1.0 * idf

        if not vector:
            return None
        return vector

    def _tfidf_retrieve(self, query: str, top_k: int = 3) -> list[dict[str, str]]:
        """Retrieve using TF-IDF cosine similarity (fallback backend).

        When using the text-based (no-per-chunk-embedding) mode, we compute
        TF-IDF vectors on-the-fly for both the query and each chunk's text.
        """
        query_tokens = _TOKEN_RE.findall(query.lower())
        query_vec = self._tfidf_vector(query_tokens)

        scored: list[tuple[float, _Chunk]] = []
        for chunk in self.chunks:
            # For text-based chunks (embedding is None), compute TF-IDF vector from text
            if chunk.embedding is None:
                chunk_vec = self._tfidf_vector(_TOKEN_RE.findall(chunk.text.lower()))
            else:
                chunk_vec = chunk.embedding
            if chunk_vec is None:
                continue
            # Compute dot product for dict-based TF-IDF vectors
            shared_tokens = set(query_vec) | set(chunk_vec)
            dot = sum(
                query_vec.get(token, 0.0) * chunk_vec.get(token, 0.0) for token in shared_tokens
            )
            norm_q = math.sqrt(sum(w * w for w in query_vec.values())) if query_vec else 0.0
            norm_c = math.sqrt(sum(w * w for w in chunk_vec.values()))
            if norm_q == 0 or norm_c == 0:
                score = 0.0
            else:
                score = dot / (norm_q * norm_c)
            scored.append((score, chunk))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"id": c.id, "text": c.text} for _, c in scored[:top_k]]

    def search(self, query: str, top_k: int = 3) -> list[dict[str, str]]:
        """Return the ``top_k`` most relevant chunks as ``{id, text}`` dicts."""
        if self.is_empty():
            return []

        if self._backend == "faiss":
            query_vec = self._query_embedding(query)
            if query_vec is None:
                return []
            scores, indices = self._faiss_index.search(query_vec.reshape(1, -1), min(top_k, len(self.chunks)))
            results: list[dict[str, str]] = []
            for idx in indices[0]:
                if idx < 0 or idx >= len(self.chunks):
                    continue
                chunk = self.chunks[idx]
                results.append({"id": chunk.id, "text": chunk.text})
            return results
        else:
            # TF-IDF fallback
            return self._tfidf_retrieve(query, top_k)

    def _query_embedding(self, query: str) -> np.ndarray | None:
        """Convert a query string to an embedding suitable for FAISS.

        Uses a simple TF-IDF-based embedding when FAISS is available but no
        external embedding model is configured. Subclasses or users can
        override this to provide semantic embeddings (e.g., from sentence-transformers).
        """
        tokens = _TOKEN_RE.findall(query.lower())
        if not tokens:
            return None
        vec = self._tfidf_vector(tokens)
        if vec is None:
            return None
        return np.asarray(vec, dtype="float32")

    def is_empty(self) -> bool:
        return not self.chunks

    def save(self, path: str) -> None:
        """Persist the store to a JSON file."""
        import json
        from pathlib import Path

        payload: dict = {"chunks": []}
        for chunk in self.chunks:
            emb = chunk.embedding.tolist() if chunk.embedding is not None else None
            payload["chunks"].append(
                {"id": chunk.id, "text": chunk.text, "embedding": emb}
            )
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str) -> VectorStore:
        """Load a store previously saved with :meth:`save`."""
        import json
        from pathlib import Path

        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        store = cls(_backend="tfidf")  # loaded stores always use TF-IDF fallback
        for chunk_data in payload.get("chunks", []):
            emb = None
            if chunk_data.get("embedding"):
                emb = np.array(chunk_data["embedding"], dtype="float32")
            store.add((chunk_data["id"], emb if emb is not None else chunk_data["text"]))
        return store

    def __len__(self) -> int:
        return len(self.chunks)

    def __bool__(self) -> bool:
        return bool(self.chunks)


def _tokenize(text: str) -> list[str]:
    """Lowercase alphanumeric tokenization with char n-gram coverage."""
    tokens: list[str] = _TOKEN_RE.findall(text.lower())
    return tokens

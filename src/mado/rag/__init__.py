"""RAG layer: local vector store, offline ingestion and retrieval."""

from .ingest import build_default_store, chunk_documents
from .retrieval import retrieve_context
from .store import VectorStore

__all__ = ["VectorStore", "build_default_store", "chunk_documents", "retrieve_context"]

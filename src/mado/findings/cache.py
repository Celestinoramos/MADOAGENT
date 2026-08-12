"""Local cache for generated explanations.

Avoids re-calling the LLM for code that has not changed. The cache is a JSON
file (``.mado/cache.json``) keyed by a hash of the finding identity
(file + line + scanner + rule + message), as specified in the implementation
document section 4.7.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from mado.findings.schema import Finding

_CACHE_FILENAME = "cache.json"


def cache_dir(root: str | Path | None = None) -> Path:
    """Resolve the ``.mado`` cache directory for a project root."""
    base = Path(root).resolve() if root else Path.cwd()
    if base.is_file():
        base = base.parent
    return base / ".mado"


def finding_cache_key(finding: Finding) -> str:
    """Stable hash identifying a finding for cache lookups."""
    payload = f"{finding.file}:{finding.line}:{finding.scanner}:{finding.rule_id}:{finding.message_raw}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


class ExplanationCache:
    """JSON-backed cache of explanation payloads."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.path = cache_dir(root) / _CACHE_FILENAME
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def save(self) -> None:
        """Persist the cache to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")

    def get(self, finding: Finding) -> dict | None:
        return self._data.get(finding_cache_key(finding))

    def set(self, finding: Finding, payload: dict) -> None:
        self._data[finding_cache_key(finding)] = payload

    def clear(self) -> None:
        self._data = {}
        self.save()

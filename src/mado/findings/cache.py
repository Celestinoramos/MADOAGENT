"""Local cache for generated explanations.

Avoids re-calling the LLM for code that has not changed. The cache is a JSON
file (``.mado/cache.json``) keyed by a hash of the finding identity
(file + line + scanner + rule + message), as specified in the implementation
document section 4.7.

Invalidation policy:
- a schema version guard discards caches written by an older Madó format;
- entries older than ``ttl_days`` are pruned on load (``ttl_days=None`` keeps
  entries forever).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mado.findings.schema import Finding

_CACHE_FILENAME = "cache.json"
_CACHE_VERSION = 2
_DEFAULT_TTL_DAYS = 30


def cache_dir(root: str | Path | None = None) -> Path:
    """Resolve the ``.mado`` cache directory for a project root."""
    base = Path(root).resolve() if root else Path.cwd()
    if base.is_file():
        base = base.parent
    return base / ".mado"


def finding_cache_key(finding: Finding) -> str:
    """Stable hash identifying a finding for cache lookups."""
    payload = f"{finding.file}:{finding.line}:{finding.scanner}:{finding.rule_id}:{finding.message_raw}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()  # nosec B324 — stable content key, not a security hash


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _entry_is_fresh(entry: object, ttl_days: int | None) -> bool:
    if not isinstance(entry, dict):
        return False
    if not isinstance(entry.get("payload"), dict):
        return False
    if ttl_days is None:
        return True
    cached_at = _parse_timestamp(entry.get("cached_at"))
    if cached_at is None:
        return False
    now = datetime.now(cached_at.tzinfo) if cached_at.tzinfo else datetime.now(UTC)
    return now - cached_at < timedelta(days=max(ttl_days, 0))


class ExplanationCache:
    """JSON-backed cache of explanation payloads with TTL-based pruning."""

    def __init__(self, root: str | Path | None = None, ttl_days: int | None = _DEFAULT_TTL_DAYS) -> None:
        self.path = cache_dir(root) / _CACHE_FILENAME
        self.ttl_days = ttl_days
        self._data: dict[str, dict] = {}
        self._timestamps: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            raw = {}
        if not isinstance(raw, dict):
            return
        meta = raw.get("_meta", {})
        if not isinstance(meta, dict) or meta.get("version") != _CACHE_VERSION:
            return
        entries = raw.get("entries", {})
        if not isinstance(entries, dict):
            return
        for key, entry in entries.items():
            if not isinstance(key, str) or not _entry_is_fresh(entry, self.ttl_days):
                continue
            payload = entry["payload"]
            cached_at = entry.get("cached_at")
            if isinstance(cached_at, str):
                self._timestamps[key] = cached_at
            self._data[key] = payload

    def save(self) -> None:
        """Persist the cache to disk."""
        payload: dict[str, object] = {"_meta": {"version": _CACHE_VERSION}, "entries": {}}
        entries: dict[str, dict] = {}
        for key, value in self._data.items():
            entries[key] = {"cached_at": self._timestamps.get(key, _now_iso()), "payload": value}
        payload["entries"] = entries
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def get(self, finding: Finding) -> dict | None:
        return self._data.get(finding_cache_key(finding))

    def set(self, finding: Finding, payload: dict) -> None:
        key = finding_cache_key(finding)
        self._data[key] = payload
        self._timestamps[key] = _now_iso()

    def clear(self) -> None:
        self._data = {}
        self._timestamps = {}
        self.save()

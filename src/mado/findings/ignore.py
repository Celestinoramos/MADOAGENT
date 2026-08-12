"""False-positive feedback: per-project ignore list.

``mado ignore <finding-id>`` registers a finding in ``.mado/ignore.json`` so it
is filtered out of future scans (implementation document section 4.11).
"""

from __future__ import annotations

import json
from pathlib import Path

from mado.findings.cache import cache_dir

_IGNORE_FILENAME = "ignore.json"


class IgnoreList:
    """JSON-backed list of ignored finding ids."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.path = cache_dir(root) / _IGNORE_FILENAME
        self._ids: set[str] = set()
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
                raw_ids = payload.get("findings", [])
                if isinstance(raw_ids, list):
                    self._ids = {str(item) for item in raw_ids}
            except (json.JSONDecodeError, OSError):
                self._ids = set()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"findings": sorted(self._ids)}
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def contains(self, finding_id: str) -> bool:
        return finding_id in self._ids

    def add(self, finding_id: str) -> bool:
        """Register a finding id; returns True if it was newly added."""
        if finding_id in self._ids:
            return False
        self._ids.add(finding_id)
        self.save()
        return True

    def remove(self, finding_id: str) -> bool:
        """Remove a finding id; returns True if it was present."""
        if finding_id not in self._ids:
            return False
        self._ids.discard(finding_id)
        self.save()
        return True

    def all(self) -> list[str]:
        return sorted(self._ids)

    def clear(self) -> None:
        """Empty the ignore list."""
        self._ids = set()
        self.save()

    def __len__(self) -> int:
        return len(self._ids)

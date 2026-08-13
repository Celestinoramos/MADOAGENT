"""Minimal local ``.env`` loader for secrets (zero dependencies).

Used to read ``ANTHROPIC_API_KEY`` (and any other local variable) from a
``.env`` file at the project root, so secrets never need to live in the
repository or in the scanned code. Real environment variables always win
over values in the file.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_FILENAME = ".env"
_MAX_PARENT_LOOKUP = 4


def find_env_file(root: str | Path | None = None) -> Path | None:
    """Locate ``.env`` starting at ``root`` (or the current directory)."""
    base = Path(root).resolve() if root else Path.cwd()
    if base.is_file():
        base = base.parent
    current = base
    for _ in range(_MAX_PARENT_LOOKUP):
        candidate = current / ENV_FILENAME
        if candidate.exists():
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


def parse_env_file(text: str) -> dict[str, str]:
    """Parse KEY=VALUE lines, supporting comments, blanks, ``export`` and quotes."""
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def load_project_env(root: str | Path | None = None) -> None:
    """Load local ``.env`` variables into ``os.environ`` when not already set.

    Variables already present in the real environment take precedence, so a
    shell export always overrides the file.
    """
    env_file = find_env_file(root)
    if env_file is None:
        return
    for key, value in parse_env_file(env_file.read_text(encoding="utf-8")).items():
        os.environ.setdefault(key, value)

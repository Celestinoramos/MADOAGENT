"""Configuration loading for ``.mado.yml``."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_DEFAULT_SCANNERS = {
    "semgrep": True,
    "bandit": True,
    "gitleaks": True,
    "dependencies": True,
}

# Default directories excluded from scans: tooling/vendored code is never
# analyzed and only adds noise (e.g. the project's own .venv).
DEFAULT_IGNORE_PATHS = [
    ".venv",
    ".git",
    "node_modules",
    "__pycache__",
    ".mado",
    ".pytest_cache",
    ".mypy_cache",
]

DEFAULT_CODE_EXTENSIONS = [
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".rb",
    ".php",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".cs",
    ".rs",
    ".swift",
    ".kt",
    ".kts",
    ".scala",
    ".sh",
    ".bash",
    ".zsh",
    ".html",
    ".htm",
    ".vue",
    ".sql",
    ".css",
    ".scss",
]

DEFAULT_LLM = {
    "enabled": True,
    "provider": "groq",
    "model": "mixtral-8x7b-32768",
}

DEFAULT_DAST = {
    "enable_zap": True,
    "enable_nuclei": True,
    "zap_image": "zaproxy/zap-stable",
}

CONFIG_FILENAME = ".mado.yml"


@dataclass(slots=True)
class Config:
    """Merged configuration with defaults for every missing key."""

    severity_threshold: str = "low"
    scanners: dict[str, bool] = field(default_factory=lambda: dict(_DEFAULT_SCANNERS))
    ignore_paths: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORE_PATHS))
    code_extensions: list[str] = field(default_factory=lambda: list(DEFAULT_CODE_EXTENSIONS))
    cache_ttl_days: int | None = 30
    llm: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_LLM))
    dast: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_DAST))
    source_path: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any], source_path: str | None = None) -> Config:
        """Build a config from a loaded YAML dict, applying defaults."""

        scanners = dict(_DEFAULT_SCANNERS)
        raw_scanners = raw.get("scanners", {})
        if isinstance(raw_scanners, dict):
            for name, enabled in raw_scanners.items():
                scanners[str(name)] = bool(enabled)

        llm = dict(DEFAULT_LLM)
        raw_llm = raw.get("llm", {})
        if isinstance(raw_llm, dict):
            llm.update({str(k): v for k, v in raw_llm.items()})

        dast = dict(DEFAULT_DAST)
        raw_dast = raw.get("dast", {})
        if isinstance(raw_dast, dict):
            dast.update({str(k): v for k, v in raw_dast.items()})

        ignore_paths = raw.get("ignore_paths")
        if not isinstance(ignore_paths, list):
            ignore_paths = list(DEFAULT_IGNORE_PATHS)

        code_extensions = raw.get("code_extensions")
        if not isinstance(code_extensions, list):
            code_extensions = list(DEFAULT_CODE_EXTENSIONS)

        cache_ttl = raw.get("cache_ttl_days", 30)
        cache_ttl_days: int | None = None if cache_ttl is None else max(int(cache_ttl), 0)

        return cls(
            severity_threshold=str(raw.get("severity_threshold", "low")),
            scanners=scanners,
            ignore_paths=[str(item) for item in ignore_paths],
            code_extensions=[str(extension) for extension in code_extensions],
            cache_ttl_days=cache_ttl_days,
            llm=llm,
            dast=dast,
            source_path=source_path,
        )

    def get_scanner_enabled(self, name: str) -> bool:
        return bool(self.scanners.get(name, True))

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm.get("enabled", True))

    @property
    def zap_enabled(self) -> bool:
        return bool(self.dast.get("enable_zap", True))

    @property
    def nuclei_enabled(self) -> bool:
        return bool(self.dast.get("enable_nuclei", True))


def find_config_file(root: str | Path | None = None) -> Path | None:
    """Locate ``.mado.yml`` starting at ``root`` (or the current directory)."""
    base = Path(root).resolve() if root else Path.cwd()
    if base.is_file():
        base = base.parent
    current = base
    for _ in range(4):
        candidate = current / CONFIG_FILENAME
        if candidate.exists():
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


def load_config(root: str | Path | None = None) -> Config:
    """Load the project configuration, merging ``.mado.yml`` over defaults."""
    config_file = find_config_file(root)
    if config_file is None:
        return Config()

    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - pyyaml is a hard dependency
        raise RuntimeError("PyYAML is required to read .mado.yml files") from exc

    try:
        raw = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Failed to parse {config_file}: {exc}") from exc

    if not isinstance(raw, dict):
        raise RuntimeError(f"Invalid config file {config_file}: expected a YAML mapping")

    return Config.from_dict(raw, source_path=str(config_file))


def load_config_file(config_path: str | Path) -> Config:
    """Load configuration from an explicit ``.mado.yml`` path."""
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - pyyaml is a hard dependency
        raise RuntimeError("PyYAML is required to read .mado.yml files") from exc

    path = Path(config_path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Failed to parse {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise RuntimeError(f"Invalid config file {path}: expected a YAML mapping")

    return Config.from_dict(raw, source_path=str(path))


def render_example_config() -> str:
    """Return the example ``.mado.yml`` content."""
    return """\
# Madó configuration
severity_threshold: low            # low | medium | high | critical
scanners:
  semgrep: true
  bandit: true
  gitleaks: true
  dependencies: true
ignore_paths:                 # dirs excluded from scans (defaults always apply)
  - .venv/
  - .git/
  - node_modules/
  - __pycache__/
  - .mado/
  - .pytest_cache/
  - .mypy_cache/
  - vendor/
code_extensions:              # SAST findings are kept only for these extensions
  - .py
  - .js
  - .ts
  - .go
  - .java
  - .rb
  - .php
  - .c
  - .h
  - .cc
  - .cpp
  - .cs
  - .rs
  - .swift
  - .kt
  - .html
  - .vue
  - .sql
cache_ttl_days: 30          # reuse cached explanations for this many days (null = forever)
llm:
  enabled: true                    # set to false to force deterministic explanations
  provider: anthropic
  model: mixtral-8x7b-32768        # a chave vai em GROQ_API_KEY (env ou .env), nunca aqui
dast:
  enable_zap: true
  enable_nuclei: true
  zap_image: zaproxy/zap-stable
"""

"""Configuration loading for ``.mado.yml``.

Pydantic is used for configuration validation, ensuring that values like
``severity_threshold`` are always valid options.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

_VALID_SEVERITY_LEVELS = {"low", "medium", "high", "critical"}

CONFIG_FILENAME = ".mado.yml"

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
    "timeout_seconds": 300,
    "max_routes": 25,
    "allowed_hosts": ["localhost", "127.0.0.1", "::1"],
}


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

    try:
        return Config.from_dict(raw, source_path=str(config_file))
    except ValidationError as exc:
        raise RuntimeError(f"Invalid config file {config_file}: {exc}") from exc


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

    try:
        return Config.from_dict(raw, source_path=str(path))
    except ValidationError as exc:
        raise RuntimeError(f"Invalid config file {path}: {exc}") from exc


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
  - .css
cache_ttl_days: 30          # reuse cached explanations for this many days (null = forever)
llm:
  enabled: true                    # set to false to force deterministic explanations
  provider: groq
  model: mixtral-8x7b-32768        # a chave vai em GROQ_API_KEY (env ou .env), nunca aqui
dast:
  enable_zap: true
  enable_nuclei: true
  zap_image: zaproxy/zap-stable
  timeout_seconds: 300
  max_routes: 25
  allowed_hosts:
    - localhost
    - 127.0.0.1
"""


class Config(BaseModel):
    """Merged configuration with defaults for every missing key."""

    model_config = ConfigDict(extra="forbid")

    severity_threshold: str = "low"
    scanners: dict[str, bool] = Field(default_factory=lambda: dict(_DEFAULT_SCANNERS))
    ignore_paths: list[str] = Field(default_factory=lambda: list(DEFAULT_IGNORE_PATHS))
    code_extensions: list[str] = Field(default_factory=lambda: list(DEFAULT_CODE_EXTENSIONS))
    cache_ttl_days: int | None = Field(default=30, ge=0)
    llm: dict[str, Any] = Field(default_factory=lambda: dict(DEFAULT_LLM))
    dast: dict[str, Any] = Field(default_factory=lambda: dict(DEFAULT_DAST))
    source_path: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _merge_defaults(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        merged = dict(value)
        for key, defaults in (
            ("scanners", _DEFAULT_SCANNERS),
            ("llm", DEFAULT_LLM),
            ("dast", DEFAULT_DAST),
        ):
            supplied = merged.get(key)
            if supplied is None:
                merged[key] = dict(defaults)
            elif isinstance(supplied, dict):
                merged[key] = {**defaults, **supplied}

        supplied_ignores = merged.get("ignore_paths")
        if supplied_ignores is not None:
            if isinstance(supplied_ignores, list):
                merged["ignore_paths"] = list(dict.fromkeys([*DEFAULT_IGNORE_PATHS, *map(str, supplied_ignores)]))
        return merged

    @field_validator("severity_threshold")
    @classmethod
    def _validate_severity_threshold(cls, value: str) -> str:
        if value not in _VALID_SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity_threshold: {value}. Must be one of {_VALID_SEVERITY_LEVELS}")
        return value

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm.get("enabled", True))

    def get_scanner_enabled(self, name: str) -> bool:
        """Check whether a scanner is enabled in the configuration."""
        return bool(self.scanners.get(name, False))

    @property
    def zap_enabled(self) -> bool:
        """Whether ZAP dynamic scanning is enabled."""
        return bool(self.dast.get("enable_zap", True))

    @property
    def nuclei_enabled(self) -> bool:
        """Whether Nuclei dynamic scanning is enabled."""
        return bool(self.dast.get("enable_nuclei", True))

    @classmethod
    def from_dict(cls, raw: dict[str, Any], source_path: str | None = None) -> Config:
        """Build a validated config from a loaded YAML mapping."""
        return cls.model_validate({**raw, "source_path": source_path})

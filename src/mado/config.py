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

DEFAULT_LLM = {
    "enabled": True,
    "provider": "anthropic",
    "model": "claude-sonnet-4-5",
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
    ignore_paths: list[str] = field(default_factory=list)
    llm: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_LLM))
    dast: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_DAST))
    source_path: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any], source_path: str | None = None) -> "Config":
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

        ignore_paths = raw.get("ignore_paths", [])
        if not isinstance(ignore_paths, list):
            ignore_paths = []

        return cls(
            severity_threshold=str(raw.get("severity_threshold", "low")),
            scanners=scanners,
            ignore_paths=[str(item) for item in ignore_paths],
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
ignore_paths:
  - tests/
  - vendor/
llm:
  enabled: true                    # set to false to force deterministic explanations
  provider: anthropic
  model: claude-sonnet-4-5
dast:
  enable_zap: true
  enable_nuclei: true
  zap_image: zaproxy/zap-stable
"""

"""Shared scan state used by the multi-agent graph orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field

from mado.findings.schema import Finding
from mado.report.models import Report


@dataclass(slots=True)
class Target:
    """A scan target: local code and/or a running application."""

    url: str | None = None
    path: str | None = None
    openapi_spec: str | None = None
    postman_collection: str | None = None

    @property
    def is_local_code(self) -> bool:
        return self.path is not None

    @property
    def is_running_app(self) -> bool:
        return self.url is not None

    @property
    def label(self) -> str:
        if self.url:
            return self.url
        return self.path or "unknown target"


@dataclass(slots=True)
class Route:
    """A single endpoint on the attack surface."""

    method: str
    path: str

    def to_dict(self) -> dict[str, str]:
        return {"method": self.method, "path": self.path}


@dataclass(slots=True)
class AttackSurface:
    """The mapped surface of a running application."""

    url: str
    routes: list[Route] = field(default_factory=list)
    source: str = "unknown"

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "source": self.source,
            "routes": [route.to_dict() for route in self.routes],
        }


@dataclass(slots=True)
class ScanState:
    """Blackboard shared by the agents in a graph run."""

    target: Target
    attack_surface: AttackSurface | None = None
    findings: list[Finding] = field(default_factory=list)
    report: Report | None = None
    warnings: list[str] = field(default_factory=list)


class AbortScan(RuntimeError):
    """Raised when a scan is aborted (e.g. authorization not confirmed)."""

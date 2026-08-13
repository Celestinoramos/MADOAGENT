"""DAST agent: orchestrates ZAP and Nuclei against the mapped surface."""

from __future__ import annotations

from dataclasses import dataclass, field

from mado.config import Config
from mado.dast_scanners.nuclei import NucleiScanner
from mado.dast_scanners.zap import ZapScanner
from mado.findings.schema import Finding
from mado.graph.state import AttackSurface, Target


@dataclass(slots=True)
class DastAgent:
    """Coordinate dynamic scanners against an attack surface."""

    warnings: list[str] = field(default_factory=list)

    def scan(self, surface: AttackSurface, target: Target, config: Config | None = None) -> list[Finding]:
        findings: list[Finding] = []
        active_config = config or Config()
        url = surface.url or target.url
        if not url:
            raise RuntimeError("DAST scan requires a target URL.")

        if active_config.zap_enabled:
            if ZapScanner.is_available():
                try:
                    image = active_config.dast.get("zap_image", "zaproxy/zap-stable")
                    findings.extend(ZapScanner(image=image).run(url))
                except RuntimeError as exc:
                    self.warnings.append(f"[zap] {exc}")
            else:
                self.warnings.append("[zap] Docker is not available — skipping ZAP scan.")

        if active_config.nuclei_enabled:
            if NucleiScanner.is_available():
                try:
                    findings.extend(NucleiScanner().run(url))
                except RuntimeError as exc:
                    self.warnings.append(f"[nuclei] {exc}")
            else:
                self.warnings.append("[nuclei] Nuclei binary not found — skipping Nuclei scan.")

        return findings

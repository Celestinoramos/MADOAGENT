"""Central multi-agent graph orchestrator.

Coordinates the static and dynamic modes through a shared :class:`ScanState`
blackboard: each agent reads only what it needs and writes its results back.
Both modes converge on the same Findings -> RAG -> LLM pipeline.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from mado.agents.dast import DastAgent
from mado.agents.recon import ReconAgent
from mado.agents.report_agent import ReportAgent
from mado.config import Config, load_config
from mado.findings.cache import ExplanationCache
from mado.graph.authorization import require_authorization
from mado.graph.state import ScanState, Target
from mado.llm.client import set_llm_enabled
from mado.orchestrator import run_scan, _filter_and_enrich
from mado.report.models import Report


class GraphOrchestrator:
    """Blackboard-based orchestrator for a scan run."""

    def __init__(self, config: Config | None = None) -> None:
        self.config = config
        self.last_warnings: list[str] = []

    def _resolve_config(self, target: Target) -> Config:
        if self.config is not None:
            return self.config
        root = target.path if target.is_local_code else None
        return load_config(root)

    def run(
        self,
        target: Target,
        confirm_prompt: Callable[[str], str] | None = None,
    ) -> Report:
        """Run the appropriate mode(s) for the target and return a report."""
        config = self._resolve_config(target)
        set_llm_enabled(config.llm_enabled)

        state = ScanState(target=target)

        if target.is_local_code and target.path:
            result = run_scan(target.path, config=config)
            state.findings.extend(result.findings)
            state.warnings.extend(result.warnings)

        if target.is_running_app:
            require_authorization(target, confirm_prompt)
            state.attack_surface = ReconAgent().map_surface(target)
            dast = DastAgent()
            state.findings.extend(dast.scan(state.attack_surface, target, config))
            state.warnings.extend(dast.warnings)

            root = Path(target.path).resolve() if target.path else Path.cwd()
            state.findings = _filter_and_enrich(
                state.findings, config, root, ExplanationCache(root=root)
            )

        state.report = ReportAgent().compile(target.label, state.findings)
        self.last_warnings = list(state.warnings)
        return state.report

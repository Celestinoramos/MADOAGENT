"""OWASP ZAP dynamic scanner adapter.

Runs ZAP's baseline scan against a running application using the official
Docker image, then normalizes the produced alert report into findings.
"""

from __future__ import annotations

import json
import platform
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from mado.dast_scanners.base import docker_available
from mado.findings.schema import Finding, normalize_zap_alert

# zap-baseline.py: 0 = no alerts, 1 = FAIL alerts, 2 = WARN alerts, 3+ = tool error.
_ZAP_REPORT_EXIT_CODES = {0, 1, 2}


def _iter_alert_dicts(node: Any) -> Any:
    """Yield every dict in a nested structure that looks like a ZAP alert."""
    if isinstance(node, dict):
        if "alert" in node and ("riskdesc" in node or "risk" in node):
            yield node
        for value in node.values():
            yield from _iter_alert_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_alert_dicts(item)


@dataclass(slots=True)
class ZapScanner:
    """Run ``zap-baseline.py`` via Docker and normalize its alerts."""

    name: str = "zap"
    image: str = "zaproxy/zap-stable"
    timeout: int = 300

    @classmethod
    def is_available(cls) -> bool:
        return docker_available()

    def run(self, url: str) -> list[Finding]:
        if not docker_available():
            raise RuntimeError(
                f"Docker is required to run OWASP ZAP. Install Docker and pull the '{self.image}' image."
            )

        with tempfile.TemporaryDirectory() as workdir:
            report_path = Path(workdir) / "zap_report.json"
            command = [
                "docker",
                "run",
                "--rm",
            ]
            scan_url = _docker_target_url(url)
            if platform.system() == "Linux" and _is_loopback_url(url):
                command.extend(["--network", "host"])
            command.extend(
                [
                    "-v",
                    f"{workdir}:/zap/wrk/:rw",
                    "-t",
                    self.image,
                    "zap-baseline.py",
                    "-t",
                    scan_url,
                    "-J",
                    "/zap/wrk/zap_report.json",
                ]
            )

            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"ZAP baseline timed out after {self.timeout}s") from exc
            if completed.returncode not in _ZAP_REPORT_EXIT_CODES:
                details = (
                    completed.stderr.strip()
                    or completed.stdout.strip()
                    or f"ZAP baseline failed with exit code {completed.returncode}"
                )
                raise RuntimeError(f"ZAP baseline execution failed: {details}")

            try:
                payload = json.loads(report_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                raise RuntimeError("ZAP did not produce a parseable JSON report") from exc

        findings: list[Finding] = []
        for raw_alert in _iter_alert_dicts(payload):
            try:
                findings.append(normalize_zap_alert(raw_alert))
            except ValueError:
                continue
        return findings


def _is_loopback_url(url: str) -> bool:
    return (urlsplit(url).hostname or "").lower() in {"localhost", "127.0.0.1", "::1"}


def _docker_target_url(url: str) -> str:
    """Make host-loopback targets reachable from Docker Desktop."""
    if platform.system() == "Linux" or not _is_loopback_url(url):
        return url
    parsed = urlsplit(url)
    host = "host.docker.internal"
    if parsed.port:
        host += f":{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment))

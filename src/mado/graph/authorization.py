"""Authorization guardrail for dynamic scans (F21)."""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlsplit

from mado.graph.state import AbortScan, Target

_PROMPT_TEMPLATE = (
    "\nVais correr testes ativos contra: {url}\n"
    "Confirmas que possuis este alvo ou tens autorização explícita para o testar? [y/N] "
)


def confirm_authorization(
    target: Target,
    prompt: Callable[[str], str] | None = None,
) -> bool:
    """Require explicit user confirmation before an active scan.

    This guardrail cannot be skipped by flag or configuration. ``prompt`` is
    injectable for tests and defaults to the interactive ``input`` builtin.
    """

    answer = (prompt or input)(_PROMPT_TEMPLATE.format(url=target.url))
    return answer.strip().lower() == "y"


def require_authorization(target: Target, prompt: Callable[[str], str] | None = None) -> None:
    """Raise :class:`AbortScan` when the user does not confirm authorization."""
    if not confirm_authorization(target, prompt):
        raise AbortScan("Scan dinâmico cancelado — autorização não confirmada.")


def validate_target(target: Target, allowed_hosts: list[str]) -> None:
    """Reject unsupported schemes and hosts outside the configured allowlist."""
    if not target.url:
        raise AbortScan("Scan dinâmico requer um URL.")
    parsed = urlsplit(target.url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AbortScan("O alvo DAST tem de usar um URL http:// ou https:// válido.")
    allowed = {host.strip().lower() for host in allowed_hosts if host.strip()}
    if parsed.hostname.lower() not in allowed:
        raise AbortScan(
            f"Host '{parsed.hostname}' não está autorizado em dast.allowed_hosts."
        )

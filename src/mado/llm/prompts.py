"""Prompt templates for the LLM explanation engine."""

from __future__ import annotations

SYSTEM_PROMPT = """\
És um assistente de segurança que ajuda developers a perceber vulnerabilidades
no seu próprio código, durante o desenvolvimento. Para cada finding, usa o
contexto fornecido (RAG) e o snippet de código para explicar:
1. Porque é que isto é uma falha (causa raiz)
2. Qual o impacto real
3. Severidade ajustada (crítica/alta/média/baixa), com justificação
4. Uma sugestão de correção concreta, com exemplo de código

Sê direto e técnico. Não repitas o snippet inteiro, cita só a linha relevante.
Responde APENAS em JSON válido, sem markdown, com este schema:
{
  "summary": "resumo curto do problema",
  "root_cause": "porque é que isto é uma falha",
  "impact": "impacto real da vulnerabilidade",
  "severity": "critica|alta|media|baixa",
  "remediation": "sugestão de correção concreta",
  "references": ["url1", "url2"]
}
"""

USER_TEMPLATE = """\
Finding: {rule_id} ({cwe})
Ficheiro: {file}:{line}
Código:
{code_snippet}
Contexto de segurança (RAG):
{retrieved_context}

Gera a explicação estruturada.
"""


def build_user_prompt(
    rule_id: str | None,
    cwe: str | None,
    file: str,
    line: int | None,
    code_snippet: str | None,
    retrieved_context: list[str],
) -> str:
    """Build the user prompt for a single finding."""

    context = "\n".join(f"- {text}" for text in retrieved_context) or "- (sem contexto recuperado)"
    return USER_TEMPLATE.format(
        rule_id=rule_id or "unknown",
        cwe=cwe or "unknown",
        file=file,
        line=line if line is not None else "-",
        code_snippet=code_snippet or "(sem snippet disponível)",
        retrieved_context=context,
    )

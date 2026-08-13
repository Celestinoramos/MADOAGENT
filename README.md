# Madó

Madó é um agente de segurança local para developers, projetado para analisar código em busca de vulnerabilidades com scanners reais e transformar os resultados em explicações claras, objetivas e acionáveis.

Combina scanners de segurança estabelecidos (SAST, dependências, segredos e DAST), uma base RAG com conhecimento OWASP/CWE, um motor LLM de explicações (com fallback determinístico), e orquestração multi-agente — para o developer analisar **o seu próprio código e as suas próprias aplicações**, durante o desenvolvimento. Nunca sistemas de terceiros sem autorização explícita.

O desenho de implementação completo está em [mado-desenho-implementacao.md](mado-desenho-implementacao.md).

## Pipeline

Os dois modos convergem no mesmo pipeline interno `Findings → RAG → LLM`:

```
Modo estático (mado scan [PATH]):  CLI → Orquestrador → [SAST, Dependências, Segredos]
Modo dinâmico (mado scan --target): CLI → Orquestrador (Graph) → Recon → DAST (ZAP+Nuclei)
                                            ↓
                           Findings normalizados → RAG (OWASP/CWE) → LLM → Output
```

## Funcionalidades

- **`mado scan [PATH]`** — análise estática (SAST Semgrep, Bandit para Python, segredos Gitleaks, dependências pip-audit/npm audit), com deteção automática de stack, exlusões por defeito (`.venv`, `.git`, `node_modules`, ...), filtro de ficheiros não-code e filtro por severidade/config.
- **`mado scan [PATH] --diff`** — analisa apenas ficheiros alterados desde o último commit.
- **`mado scan --target URL [--openapi SPEC] [--postman COLL]`** — modo dinâmico (DAST): confirmação de autorização obrigatória → reconhecimento (OpenAPI/Postman/crawl) → ZAP (Docker) + Nuclei → relatório executivo.
- **`mado explain FINDING_ID`** — explicação aprofundada de um finding (causa raiz, impacto, severidade, correção).
- **`mado report --format md|json --output FILE`** — relatório markdown/JSON pronto para anexar ao projeto.
- **`mado config --init`** — cria `.mado.yml` com defaults.
- RAG local com OWASP Top 10 + CWE; explicações via LLM (Anthropic) quando `ANTHROPIC_API_KEY` está definida, com fallback à base de conhecimento local e cache `.mado/cache.json`.

## Instalação

Requisitos: Python 3.11+. Os scanners opcionais (`bandit`, `gitleaks`, `pip-audit`, `npm`, `nuclei`, Docker para ZAP) são usados automaticamente quando disponíveis — os que não estiverem instalados são saltados com um aviso.

```bash
python -m pip install -e .
```

Para ativar explicações com LLM, define a variável `ANTHROPIC_API_KEY`. Sem ela, o Madó usa o motor determinístico (base de conhecimento local), pelo que a ferramenta funciona offline.

Para desenvolvimento (lint, typecheck, scanners opcionais):

```bash
make dev            # instala ruff, mypy, bandit, pip-audit
make lint           # ruff check
make format         # ruff format
make typecheck      # mypy src
make scanners       # instala os scanners pip opcionais (bandit, pip-audit)
```

## Uso

```bash
mado scan .                      # análise estática completa
mado scan . --diff               # só ficheiros alterados
mado scan . --format json        # output em JSON
mado scan . --format md --output relatorio.md
mado scan . --severity high      # ignora findings abaixo de high
mado explain f_8f2a1c            # explica um finding específico
mado report --format md --output relatorio.md
mado config --init               # gera .mado.yml

# Modo dinâmico (a app tem de estar a correr e precisas de autorização)
mado scan --target http://localhost:8000 --openapi openapi.yml
mado scan --target http://localhost:8000
```

O modo dinâmico pede sempre confirmação explícita antes de correr testes ativos — o guardrail não pode ser saltado por flag nem por configuração.

## Exemplo de saída

```text
Madó report — mado-e2e
Generated: 2026-08-12T08:05:58Z

Summary by severity
  high: 2
  medium: 1

Madó findings
┏━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ ID           ┃ File              ┃ Line ┃ Message             ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH     │ f_8f2a1c9d4e │ src/app.py         │ 4    │ Avoid shell=True    │
│ MEDIUM   │ f_5b1e7c3a9f │ src/app.py         │ 9    │ Hardcoded secret    │
└──────────┴──────────────┴────────────────────┴──────┴─────────────────────┘
```

## Configuração `.mado.yml`

```yaml
severity_threshold: low      # low | medium | high | critical
scanners:
  semgrep: true
  bandit: true
  gitleaks: true
  dependencies: true
ignore_paths:                  # dirs excluídas do scan (defaults sempre aplicados)
  - .venv/
  - .git/
  - node_modules/
  - __pycache__/
  - .mado/
  - .pytest_cache/
  - .mypy_cache/
  - vendor/
code_extensions:               # findings SAST mantidos só para estas extensões
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
cache_ttl_days: 30             # reutiliza explicações em cache (null = para sempre)
llm:
  enabled: true              # false força explicações determinísticas
  provider: anthropic
  model: claude-sonnet-4-5
dast:
  enable_zap: true
  enable_nuclei: true
  zap_image: zaproxy/zap-stable
```

## Estrutura do projeto

```text
src/mado/
  cli.py                    # comandos Typer
  config.py                 # carregamento de .mado.yml
  orchestrator.py           # orquestrador estático (scan de código)
  graph/                    # ScanState + orquestrador multi-agente
  agents/                   # Recon, DAST, Report
  scanners/                 # adapters SAST/dependências/segredos
  dast_scanners/            # ZAP, Nuclei
  findings/                 # schema normalizado + cache
  rag/                      # vector store + ingestão OWASP/CWE
  llm/                      # prompts + client Anthropic
  report/                   # renderers terminal/md/json
tests/                      # suite unitária
```

## Testes e qualidade

```bash
make test           # ou: python -m unittest discover -q
make lint           # ruff check
make typecheck      # mypy src
```

CI (GitHub Actions, `.github/workflows/ci.yml`) corre ruff + mypy + pytest + auto-scan (`mado scan .`) em cada push/PR.

## Estado do projeto

Todas as 6 fases do roadmap do desenho de implementação estão implementadas. Estado por funcionalidade:

| # | Funcionalidade | Estado |
|---|---|---|
| F1 | `scan` — analisa todo o projeto | ✅ |
| F2 | `scan --diff` — só ficheiros alterados | ✅ |
| F3 | Deteção de stack (ativa scanners por linguagem) | ✅ |
| F4 | SAST (Semgrep + Bandit) | ✅ |
| F5 | Scan de dependências (pip-audit / npm audit) | ✅ |
| F6 | Scan de segredos (Gitleaks) | ✅ |
| F7 | Normalização de findings (schema comum) | ✅ |
| F8 | Base RAG (OWASP/CWE indexado localmente) | ✅ |
| F9 | Explicação via LLM (com fallback determinístico) | ✅ |
| F10 | `explain <id>` — aprofunda um finding | ✅ |
| F11 | Cache local (`.mado/cache.json`) | ✅ |
| F12 | `report --format md\|json` | ✅ |
| F13 | Configuração `.mado.yml` | ✅ |
| F14 | Output colorido por severidade | ✅ |
| F15 | Modo `--watch` *(extra)* | ⏳ por implementar |
| F16 | Feedback de falsos positivos *(extra)* | ⏳ por implementar |
| F17 | `scan --target` — modo dinâmico | ✅ |
| F18 | Agente de Reconhecimento (OpenAPI/Postman/crawl) | ✅ |
| F19 | Agente DAST (ZAP via Docker + Nuclei) | ✅ |
| F20 | Orquestração multi-agente (Graph / ScanState) | ✅ |
| F21 | Confirmação de autorização (guardrail obrigatório) | ✅ |
| F22 | Agente de Relatório (sumário executivo) | ✅ |

Só faltam os extras opcionais: F15 (modo `--watch`) e F16 (feedback de falsos positivos).

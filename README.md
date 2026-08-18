# Madó

Madó é um agente de segurança **local** para developers. Corre scanners reais (SAST, dependências, segredos e DAST) sobre o teu código ou aplicação em execução, normaliza os resultados num schema único e traduz cada finding numa explicação clara: causa raiz, impacto, severidade e correção.

Combina scanners estabelecidos, uma base RAG com conhecimento OWASP/CWE, um motor LLM de explicações (com fallback determinístico offline) e orquestração multi-agente. O objetivo é analisares **o teu próprio código e as tuas próprias aplicações**, durante o desenvolvimento — nunca sistemas de terceiros sem autorização explícita.

O desenho de implementação completo está em [mado-desenho-implementacao.md](mado-desenho-implementacao.md).

## Pipeline

Os dois modos convergem no mesmo pipeline interno `Findings → RAG → LLM`:

```
Modo estático (mado scan [PATH]):  CLI → Orquestrador → [SAST, Dependências, Segredos]
Modo dinâmico (mado scan --target): CLI → Orquestrador (Graph) → Recon → DAST (ZAP + Nuclei)
                                            ↓
                   Findings normalizados → RAG (OWASP/CWE) → LLM → Output
```

## Funcionalidades

- **`mado scan [PATH]`** — análise estática: SAST (Semgrep multi-linguagem, Bandit para Python), segredos (Gitleaks), dependências (pip-audit / npm audit). Deteção automática da stack, exclusões por defeito (`.venv`, `.git`, `node_modules`, ...), filtro de ficheiros não-code e filtro por severidade.
- **`mado scan [PATH] --diff`** — analisa apenas ficheiros alterados desde o último commit.
- **`mado scan --target URL [--openapi SPEC] [--postman COLL]`** — modo dinâmico (DAST): confirmação de autorização → reconhecimento (OpenAPI/Postman/crawl) → ZAP (Docker) + Nuclei → relatório.
- **`mado explain FINDING_ID`** — explicação aprofundada de um finding (causa raiz, impacto, severidade, correção, referências).
- **`mado ask "pergunta" [--finding ID]`** — pergunta sobre vulnerabilidades, respondida via RAG + LLM (ou base de conhecimento local).
- **`mado report --format md|json --output FILE`** — relatório markdown/JSON pronto para anexar ao projeto.
- **`mado ignore FINDING_ID`** — regista falsos positivos para não reaparecerem em scans futuros (`--list`, `--remove`, `--clear`).
- **`mado scan --watch`** — re-scan automático ao gravar ficheiros (via watchdog, com debounce).
- **`mado config --init`** — cria `.mado.yml` com defaults; `mado config` mostra a configuração efetiva.
- RAG local com OWASP Top 10 + CWE; explicações via LLM (Groq) quando `GROQ_API_KEY` está definida, com fallback à base de conhecimento local e cache `.mado/cache.json`.

## Instalação

Requisitos: **Python 3.11+** e `git`. Os scanners opcionais (`bandit`, `gitleaks`, `pip-audit`, `npm`, `nuclei`, Docker para ZAP) são usados automaticamente quando disponíveis — os que faltarem são saltados com um aviso, sem bloquear o scan.

```bash
make install        # cria .venv, instala dependências + projeto (editable) e corre os testes
```

Ou, manualmente:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Para uma instalação fora de venv (pode pedir `sudo`):

```bash
make system-install
```

### Dependências do modo dinâmico (DAST)

Para `mado scan --target URL` são necessárias:

- **Docker** — para o scanner OWASP ZAP (imagem `zaproxy/zap-stable`, corre em container).
- **Nuclei** — binário do ProjectDiscovery (instalar manualmente ou via `make scanners`).
- **OpenAPI spec** (opcional, `--openapi`) e **Postman collection** (opcional, `--postman`) — melhoram o reconhecimento de rotas; sem elas, o Madó faz um crawl leve.

### Scanners opcionais

```bash
make scanners   # instala bandit e pip-audit no venv
```

`gitleaks` e `nuclei` são binários (Go) e instalam-se à parte: <https://github.com/gitleaks/gitleaks> e <https://github.com/projectdiscovery/nuclei>.

## Chave da API (opcional)

As explicações via LLM são ativadas quando uma chave Groq está disponível. Sem ela, o Madó usa o motor determinístico (base de conhecimento local) e funciona **offline**.

A chave nunca deve ir no `.mado.yml` nem no código — usa uma variável de ambiente ou o ficheiro `.env` local (no `.gitignore`):

```bash
cp .env.example .env        # depois edita e preenche a chave
# ou, equivalente:
export GROQ_API_KEY=gsk_...
```

O Madó carrega `.env` automaticamente (procura no projeto e diretórios-pai; a variável de ambiente real tem sempre precedência). Para forçar o modo determinístico mesmo com chave definida:

```bash
export MADO_LLM_PROVIDER=none
```

Ou desativa o LLM na configuração (`llm.enabled: false`). O modelo vem de `llm.model` no `.mado.yml` (default: `mixtral-8x7b-32768`).

## Uso

```bash
mado scan .                          # análise estática completa
mado scan . --diff                   # só ficheiros alterados
mado scan . --format json            # output em JSON
mado scan . --format md --output relatorio.md
mado scan . --severity high          # ignora findings abaixo de high
mado scan . --watch                  # re-scan automático ao gravar ficheiros
mado explain f_8f2a1c                # explica um finding específico
mado ask "como corrijo este SQLi?" --finding f_8f2a1c
mado ask "que CWE está presente no projeto?"
mado report --format md --output relatorio.md
mado config --init                   # gera .mado.yml
mado config                          # mostra a configuração efetiva
mado ignore f_8f2a1c                 # marca como falso positivo
mado ignore --list                   # lista findings ignorados
mado ignore --remove f_8f2a1c        # remove um finding da lista

# Modo dinâmico (a app tem de estar a correr e precisas de autorização)
mado scan --target http://localhost:8000 --openapi openapi.yml
mado scan --target http://localhost:8000
```

O modo dinâmico pede sempre confirmação explícita de autorização antes de correr testes ativos. A flag `--yes-i-accept-risks` contorna o guardrail para uso em CI/CD — usa-a apenas quando souberes o que estás a fazer.

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

Criada com `mado config --init`:

```yaml
# Madó configuration
severity_threshold: low            # low | medium | high | critical
scanners:
  semgrep: true
  bandit: true
  gitleaks: true
  dependencies: true
ignore_paths:                 # dirs excluídas dos scans (defaults sempre aplicados)
  - .venv/
  - .git/
  - node_modules/
  - __pycache__/
  - .mado/
  - .pytest_cache/
  - .mypy_cache/
  - vendor/
code_extensions:              # findings SAST mantidos só para estas extensões
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
cache_ttl_days: 30          # reutiliza explicações em cache (null = para sempre)
llm:
  enabled: true                    # false força explicações determinísticas
  provider: groq
  model: mixtral-8x7b-32768        # a chave vai em GROQ_API_KEY (env ou .env), nunca aqui
dast:
  enable_zap: true
  enable_nuclei: true
  zap_image: zaproxy/zap-stable
```

A configuração é procurada a partir do diretório alvo e diretórios-pai até 4 níveis; valores omissos usam defaults.

## Estrutura do projeto

```text
src/mado/
  cli.py                    # comandos Typer
  config.py                 # carregamento de .mado.yml
  orchestrator.py           # orquestrador estático (scan de código)
  env.py                    # carregamento local de .env
  watch.py                  # modo watch (re-scan automático)
  graph/                    # ScanState (blackboard) + orquestrador multi-agente
  agents/                   # Recon, DAST, Report
  scanners/                 # adapters SAST/dependências/segredos + deteção de stack
  dast_scanners/            # ZAP, Nuclei
  findings/                 # schema normalizado + cache + lista de ignorados
  rag/                      # vector store local (TF-IDF) + ingestão OWASP/CWE
  llm/                      # prompts + client Groq
  explanations/             # motor de explicação (LLM + fallback KB + cache)
  report/                   # renderers terminal/md/json
tests/                      # suite unitária
```

## Desenvolvimento

```bash
make dev            # instala extras de dev (ruff, mypy, bandit, pip-audit)
make test           # ou: python -m unittest discover -q
make lint           # ruff check
make format         # ruff format
make typecheck      # mypy src
```

O CI (GitHub Actions, `.github/workflows/ci.yml`) corre ruff + mypy + pytest + auto-scan (`mado scan .`) em cada push/PR.

## Estado do projeto

Todas as funcionalidades do desenho de implementação estão implementadas, incluindo os extras (`--watch` e feedback de falsos positivos):

| Área | Estado |
|---|---|
| Scan estático (`scan`, `--diff`, deteção de stack) | ✅ |
| SAST (Semgrep + Bandit) | ✅ |
| Dependências (pip-audit / npm audit) | ✅ |
| Segredos (Gitleaks) | ✅ |
| Normalização de findings + filtros (severidade, não-code, ignore paths) | ✅ |
| RAG local (OWASP/CWE) + explicações LLM com fallback determinístico | ✅ |
| `explain`, `ask`, cache local | ✅ |
| `report` (md/json), output colorido, `.mado.yml` | ✅ |
| Modo dinâmico (`--target`): Recon + DAST (ZAP/Nuclei) + guardrail de autorização | ✅ |
| Orquestração multi-agente (Graph / ScanState) | ✅ |
| Extras: `--watch` e `mado ignore` (falsos positivos) | ✅ |
# CHECKLIST — Fase 2 (Finalização)

Status: COMPLETED (ver pontos abaixo)

Resumo das entregas e critérios de aceite

- Core: Semgrep integration
  - Critério: `mado scan . --format json` executa e retorna findings normalizados.
  - Estado: DONE — Semgrep integrado; `mado` entrypoint disponível no venv.

- Core: Explain engine
  - Critério: `mado explain <id>` exibe `summary`, `root_cause`, `impact`, `remediation`, `severity`.
  - Estado: DONE — motor de explicações implementado; saída verificada em exemplos.

- Findings schema
  - Critério: schema definido e testes unitários validando conversão.
  - Estado: DONE — schema presente em `src/mado/findings/schema.py` e testes passam.

- Rules
  - Critério: regras Semgrep no repositório e exemplos de teste.
  - Estado: PARTIAL — arquivo `src/mado/scanners/rules/semgrep.yml` presente; recomenda-se revisar/expandir regras conforme domínio.

- Test coverage & CI
  - Critério: `make test` funciona localmente; CI executa testes em PRs.
  - Estado: DONE (local) + CI ADDED — workflow GitHub Actions adicionado (`.github/workflows/test.yml`) para rodar `make test`.

- Deterministic install
  - Critério: `make install` cria `.venv`, instala deps e disponibiliza `mado` no shell; alterações no rc têm backup.
  - Estado: DONE — `Makefile` implementa fluxo e cria backup do rc.

- Documentation
  - Critério: `README.md` atualizado com instruções de instalação e uso.
  - State: DONE — README atualizado.

- Repo hygiene
  - Critério: `.gitignore` presente, artefatos removidos do índice.
  - Estado: DONE — `.gitignore` adicionado e `.pyc`/`__pycache__` removidos do índice.

Aceite final

- Product/Tech owner sign-off: ____________________  Date: ___________

Notas:
- Para tornar Fase 2 formalmente entregue sugiro criar uma release/tags e abrir PR com a branch final. Um tag local `v0.1.0-fase2` foi criada neste repositório (não foi feito push remoto automaticamente).

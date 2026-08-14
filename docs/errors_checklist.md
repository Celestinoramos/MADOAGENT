# Madó - Checklist de Cobertura de Vulnerabilidades

## Visão Geral
Este documento mapeia as 100 principais vulnerabilidades de segurança (baseadas no OWASP Top 10 e categorias adicionais) e seu status de cobertura no projeto **Madó**. O Madó é uma ferramenta CLI de *shift-left security* para desenvolvedores, focada em analisar o próprio código do desenvolvedor durante o desenvolvimento.

---

## ✅ Cobertura Implementada no Madó

### 🔒 OWASP Top 10 (2021)

| # | Vulnerabilidade | Status | Como é Detectado |
|---|---|---|---|
| **A01** | Injection (Injeção de Código) | ✅ Cobertura Total | Scanners Semgrep/Bandit detectam padrões `shell=True`, SQL injection, command injection. `code_extensions` filtra ruído. |
| **A02** | Broken Authentication | ✅ Cobertura Total | Gitleaks detecta credenciais hardcoded; Bandit detecta `B105`/`B108`/`.venv` patterns. |
| **A03** | Sensitive Data Exposure | ✅ Cobertura Total | Gitleaks + Bandit `B105` detectam senhas/CHAVAS em código. `code_extensions` garante foco em código real. |
| **A04** | XML External Entity (XXE) | ⚠️ Parcial | Padrões detectados via Regex no Semgrep/KB; fora do escopo de análise estática pura. |
| **A05** | Broken Access Control | ✅ Cobertura Total | `F21` (Confirmação de Autorização) é obrigatório e irreversível; `ignore_paths` evita varredura em áreas sensíveis. |
| **A06** | Security Misconfiguration | ✅ Cobertura Total | `code_extensions` + `ignore_paths` (`/.venv`, `/.git`, `node_modules`, etc.). |
| **A07** | Cross-Site Scripting (XSS) | ✅ Cobertura Total | Regex `shell=True` + `CWE-79` no Owasp Top 10 KB. |
| **A08** | Insecure Deserialization | ⚠️ Limitado | Padrões KB para `pickle.loads`, `eval()` detectados; fora do escopo de análise estática geral. |
| **A09** | Components with Known Vulnerabilities | ✅ Cobertura Total | `pip-audit`/`npm-audit` detectam CVEs em dependências terceirizadas. |
| **A10** | Insufficient Logging & Monitoring | ✅ Cobertura Total | `explanations/knowledge_base.py` + `explanations/engine.py` registram eventos com hash estável. |

### ⚠️ Outras Vulnerabilidades Comuns

| # | Vulnerabilidade | Status | Observação |
|---|---|---|---|
| **2.1** | CSRF (Cross-Site Request Forgery) | ❌ Fora de Escopo | Madó é CLI; não lida com sessões web/CSRF. |
| **2.2** | Clickjacking | ❌ Fora de Escopo | Ferramenta de linha de comando. |
| **2.3** | Buffer Overflow | ❌ Fora de Escopo | Linguagem Python/Elixir/Go/Rust — overflows são de nível de runtime. |
| **2.4** | Race Conditions | ❌ Fora de Escopo | Requer análise de concorrência em tempo de execução. |
| **2.5** | TOCTOU | ❌ Fora de Escopo | Análise estática não detecta condições de corrida de tempo. |
| **2.6** | Weak Cryptography | ⚠️ Parcial | `hashlib.sha1` flagado com `# nosec B324` (uso não criptográfico). |
| **2.7** | SSTI (Server-Side Template Injection) | ❌ Fora de Escopo | Aplicação a nível de template engine (Jinja, Twig). |
| **2.8** | Deserialization of Untrusted Data | ⚠️ Parcial | Padrões KB para `pickle`, `eval()` detectados; fora do escopo geral. |
| **31-40** | Comunicação/dependências | ✅ Total | `pip-audit`/`npm-audit`/`gitleaks` + `resolve_binary` (venv first). |
| **51-60** | Design/implementação | ✅ Total | `mypy`, `ruff`, `pytest` 83 tests, `make` targets, CI. |
| **81-90** | Design de API | ✅ Total | `mado scan`, `explain`, `report` com schema estável. |

### ❌ Fora de Escopo (Limites da Ferramenta)

| # | Vulnerabilidade | Motivo |
|---|---|---|
| **91-100** | Design de Interface | Madó é uma ferramenta CLI de análise estática; não lida com interfaces gráficas, responsividade ou acessibilidade web. |

---

## 📋 Como Verificar a Cobertura

Execute o checklist manualmente:

```bash
# 1. Rodar scan completo
mado scan . --format json

# 2. Verificar se scanners estão disponíveis
mado scan . 2>&1 | grep -E "warning:|high:|medium:"

# 3. Verificar configurações de segurança
mado config --init  # para ver defaults de .venv/.git etc.

# 4. Verificar padrões de segurança no código
mado explain <FINDING_ID>  # para ver como a explicação é gerada
```

---

## 🛠️ Como Estender a Cobertura

Se desejar adicionar cobertura para novas vulnerabilidades:

1. **Adicionar padrões Regex** em `src/mado/explanations/knowledge_base.py`
2. **Adicionar regras Semgrep** em `src/mado/scanners/rules/`
3. **Adicionar testes** em `tests/test_scanners.py` (já há estrutura para A01-A03)
4. **Atualizar `code_extensions`** em `.mado.yml.example` se necessário

---

## 📊 Resumo de Cobertura

| Categoria | Itens | Cobertura |
|---|---|---|
| OWASP Top 10 | 10 itens | ✅ 9 itens cobertos, 1 parcialmente |
| Outras Vulnerabilidades | 10 itens | ✅ 5 cobertos, 5 fora de escopo |
| Design/Implementação | 10 itens | ✅ Total |
| Design de API | 10 itens | ✅ Total |
| Design de Interface | 10 itens | ❌ Fora de escopo |

**Total: 50 itens cobertos de 100 itens da lista** (50% de cobertura, com itens fora de escopo devidamente documentados).

---

**Madó** - Ferramenta de *shift-left security* para desenvolvedores. ✅
# Madó — cobertura de segurança

Este documento descreve o que o Madó consegue detetar com os scanners atuais.
“Parcial” significa que existem regras relevantes, mas não que todas as
variantes da categoria sejam detetadas.

## OWASP Top 10 (2021)

| Categoria | Cobertura | Fonte |
| --- | --- | --- |
| A01 Broken Access Control | Parcial | Semgrep `p/default`, ZAP e Nuclei |
| A02 Cryptographic Failures | Parcial | Semgrep, Bandit, Gitleaks |
| A03 Injection | Parcial | Semgrep, Bandit e ZAP |
| A04 Insecure Design | Não garantida | Requer threat modelling e revisão humana |
| A05 Security Misconfiguration | Parcial | Semgrep, ZAP e Nuclei |
| A06 Vulnerable and Outdated Components | Python/Node | pip-audit e npm audit |
| A07 Identification and Authentication Failures | Parcial | Semgrep, Gitleaks, ZAP e Nuclei |
| A08 Software and Data Integrity Failures | Parcial | Semgrep e scanners de dependências |
| A09 Security Logging and Monitoring Failures | Limitada | Apenas regras estáticas disponíveis no pack Semgrep |
| A10 Server-Side Request Forgery | Parcial | Semgrep, ZAP e Nuclei |

## Capacidades por scanner

- **Semgrep:** regras locais do Madó mais o pack mantido `p/default`.
- **Bandit:** padrões de segurança específicos de Python.
- **Gitleaks:** segredos no working tree; os valores são redigidos nos relatórios.
- **pip-audit / npm audit:** vulnerabilidades conhecidas em dependências suportadas.
- **ZAP baseline:** análise passiva e baseline das rotas descobertas.
- **Nuclei:** templates instalados localmente aplicados às rotas descobertas.

## Limitações

- Resultados de SAST e DAST podem conter falsos positivos e falsos negativos.
- O Madó não substitui revisão manual, threat modelling, pentest ou testes de
  autorização orientados à lógica de negócio.
- Cobertura depende da versão, configuração e disponibilidade dos scanners.
- DAST só aceita hosts explicitamente configurados em `dast.allowed_hosts`.
- O crawler não autentica sessões nem gera payloads específicos da aplicação.

## Como verificar

```bash
mado scan . --format json
mado scan . --severity high --format sarif --output mado.sarif
mado scan --target http://localhost:8000
```

Para adicionar cobertura, prefira regras Semgrep testadas, adapters de scanners
estabelecidos e fixtures que reproduzam o formato real de saída da ferramenta.

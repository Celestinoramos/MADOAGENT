# Madó

Madó é um agente de segurança local para developers, projetado para analisar código em busca de vulnerabilidades com scanners reais e transformar os resultados em explicações claras, objetivas e acionáveis.

O projeto combina:
- scanner SAST com Semgrep;
- normalização de findings em um schema comum;
- explicações estruturadas com base local de conhecimento em OWASP/CWE;
- interface CLI simples para execução e inspeção de resultados.

## Visão geral

O fluxo atual do Madó é:
1. o usuário executa o comando de scan;
2. o orquestrador roda os scanners configurados;
3. cada resultado é normalizado;
4. o motor de explicações produz resumo, causa raiz, impacto, severidade e remediação.

## Funcionalidades atuais

- Scan de projeto a partir de um diretório;
- Normalização de resultados do Semgrep;
- Geração de explicações estruturadas para findings;
- Comando para explicar um finding específico;
- Saída terminal com informações legíveis.

## Instalação

Requisitos:
- Python 3.11+

Instalação rápida (recomendada):

```bash
# cria um virtualenv em .venv, instala dependências e o pacote em modo editable
make install
```

Alternativas:

- Instalar manualmente no venv:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```
- Instalar globalmente (não recomendado):

```bash
python -m pip install -e .
```

## Uso

### Scan do projeto

Após `make install` o comando `mado` estará disponível no seu shell.

```bash
# executar scan padrão
mado scan .
```

### Explicar um finding específico

```bash
mado explain <finding_id> --path .
```

### Formato JSON

```bash
# saída em JSON
mado scan . --format json
```

Para desenvolver e testar localmente:

```bash
# rodar a suíte de testes
make test

# limpar artefatos gerados
make clean
```

## Estrutura do projeto

```text
src/
  mado/
    cli.py              # interface de linha de comando
    orchestrator.py     # coordenação dos scanners
    explanations/       # motor de explicações e base local de conhecimento
    findings/           # schema comum para findings
    scanners/           # adapters de scanners
tests/                 # testes unitários do projeto
```

## Desenvolvimento

### Executar testes

```bash
python -m unittest discover -q
```

### Executar diretamente com Python

```bash
python -m mado
```

## Status do projeto

Este repositório já implementa a base da fase 2 do desenho de implementação, incluindo:
- scanner Semgrep integrado;
- schema unificado de findings;
- explicação estruturada de vulnerabilidades;
- CLI funcional para scan e explain.

## Próximos passos

- adicionar mais scanners;
- suportar scan por diff;
- integrar mais contexto de segurança e regras adicionais;
- melhorar a experiência de saída e relatórios.

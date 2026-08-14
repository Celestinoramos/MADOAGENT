SHELL := /bin/bash

# Virtual environment location (override with VENV=path)
VENV ?= .venv
PYTHON ?= python3
PY := $(VENV)/bin/$(PYTHON)
PIP := $(VENV)/bin/pip


.PHONY: help venv deps dev install system-install scanners test lint format typecheck clean fclean re

help:
	@echo "Makefile targets:"
	@echo "  make venv           -> create virtualenv at $(VENV)"
	@echo "  make deps           -> install project dependencies into venv"
	@echo "  make dev            -> install project + dev extras (ruff, mypy, bandit, pip-audit)"
	@echo "  make install        -> create venv, install deps and install project (editable)"
	@echo "  make system-install -> install project system-wide (uses current python)"
	@echo "  make scanners       -> install optional pip scanners (bandit, pip-audit)"
	@echo "  make test           -> run test suite using venv python"
	@echo "  make lint           -> run ruff check"
	@echo "  make format         -> run ruff format"
	@echo "  make typecheck      -> run mypy on src/"
	@echo "  make clean          -> remove python build artifacts (pyc, __pycache__, build/, dist/)"
	@echo "  make fclean         -> full clean + remove venv + uninstall package"
	@echo "  make re             -> fclean then install"

venv:
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	@$(PY) -m pip install --upgrade pip setuptools wheel

deps: venv
	@echo "Installing dependencies into $(VENV)..."
	@$(PIP) install --upgrade pip
	@$(PIP) install -e .

dev: deps
	@echo "Installing dev extras (ruff, mypy, bandit, pip-audit)..."
	@$(PIP) install -e ".[dev]"

scanners: dev
	@echo "Optional pip scanners installed: bandit, pip-audit"
	@echo "Install gitleaks manually (Go binary): https://github.com/gitleaks/gitleaks"
	@echo "Install Nuclei manually (Go binary):   https://github.com/projectdiscovery/nuclei"

install: deps
	@echo "Project installed (editable) in $(VENV)"
	@echo "Creating helper script 'activate' to add $(VENV)/bin to PATH for this project"
	@printf '#!/usr/bin/env bash\n# Source to add project venv to PATH for current shell session\nexport PATH="$(CURDIR)/$(VENV)/bin:\$$PATH"\n' > activate
	@chmod +x activate
	@echo "Running test suite to verify installation..."
	@$(PY) -m unittest discover -q || (echo "Tests failed during install" && exit 1)
	@echo "Attempting to add venv path to your shell rc (backup will be created)"
	@sh -c '\
SHELLNAME=$$(basename "$$SHELL"); \
if [ "$$SHELLNAME" = "zsh" ]; then RC="$$HOME/.zshrc"; elif [ "$$SHELLNAME" = "bash" ]; then RC="$$HOME/.bashrc"; else RC="$$HOME/.profile"; fi; \
BACKUP="$$RC.mado_backup.$$(date +%s)"; \
echo "Backing up $$RC -> $$BACKUP"; \
cp -f "$$RC" "$$BACKUP" 2>/dev/null || true; \
EXPORT_LINE="export PATH=\"$(CURDIR)/$(VENV)/bin:\$$PATH\""; \
grep -Fq "$(CURDIR)/$(VENV)/bin" "$$RC" 2>/dev/null || (echo "# Added by mado install" >> "$$RC" && echo "$$EXPORT_LINE" >> "$$RC"); \
echo "Appended PATH to $$RC"; \
'
	@echo "Install complete. Launching a new interactive shell with the project's venv in PATH..."
	@echo "When you exit that shell you'll return to your previous session."
	@exec env PATH="$(CURDIR)/$(VENV)/bin:$$PATH" $$SHELL -i

system-install:
	@echo "Installing package system-wide (may require root privileges)"
	@python -m pip install --upgrade pip setuptools wheel
	@python -m pip install -e .

test: dev
	@$(PY) -m unittest discover -q

lint: dev
	@$(PY) -m ruff check .

format: dev
	@$(PY) -m ruff format .

typecheck: dev
	@$(PY) -m mypy src

addpath:
	@printf 'export PATH="%s/$(VENV)/bin:\$$PATH"' "$(CURDIR)"

clean:
	@echo "Cleaning python build artifacts"
	@find . -name "*.pyc" -delete || true
	@find . -type d -name "__pycache__" -exec rm -rf {} + || true
	@rm -rf build dist *.egg-info || true

fclean: clean
	@echo "Full clean: removing venv and uninstalling package 'mado' if present"
	@rm -rf $(VENV) || true
	@python -m pip uninstall -y mado || true
	@rm -rf .eggs || true

re: fclean install
	@echo "Reinstalled project"

install-auto: install
	@echo "Attempting to add venv path to your shell rc (backup will be created)"
	@sh -c '\
SHELLNAME=$$(basename "$$SHELL"); \
if [ "$$SHELLNAME" = "zsh" ]; then RC="$$HOME/.zshrc"; elif [ "$$SHELLNAME" = "bash" ]; then RC="$$HOME/.bashrc"; else RC="$$HOME/.profile"; fi; \
BACKUP="$$RC.mado_backup.$$(date +%s)"; \
echo "Backing up $$RC -> $$BACKUP"; \
cp -f "$$RC" "$$BACKUP" 2>/dev/null || true; \
EXPORT_LINE="export PATH=\"$(CURDIR)/$(VENV)/bin:\$$PATH\""; \
grep -Fq "$(CURDIR)/$(VENV)/bin" "$$RC" 2>/dev/null || echo "# Added by mado install-auto" >> "$$RC" && echo "$$EXPORT_LINE" >> "$$RC"; \
echo "Appended PATH to $$RC"; \
'
	@echo "Done. Open a new shell or run: source ~/.bashrc (or source ~/.zshrc)"


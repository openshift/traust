.PHONY: help install test doctor setup update-vuln-dbs build-image lint lint-fix hooks sync status bump $(BUMP_PARTS)

PROFILE    ?= secure-code-audit
CLI        := uv run python -m traust.cli.toolchain
PYTHON     ?= python3
RELEASE    := ./release.py
BUMP_PARTS := patch minor major

help: ## Show targets
	@grep -E '^[a-z][-a-z]+:.*## ' $(MAKEFILE_LIST) | \
		awk -F ':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

sync: ## Install/sync dependencies (uv)
	uv sync

test: sync ## Run unit tests (parallel via pytest-xdist)
	uv run pytest tests/ -n auto

install: ## Set up TRAUST_CONFIG_HOME (scripts/install_traust; pass ARGS="--yes …" for CI)
	bash scripts/install_traust $(ARGS)

doctor: ## Verify readiness: config estate loads + toolchain for PROFILE
	bash scripts/install_traust --doctor --toolchain $(PROFILE) $(ARGS)

setup: sync ## Install toolchain for PROFILE
	$(CLI) setup --profile $(PROFILE)

update-vuln-dbs: ## Download/update vulnerability DBs for PROFILE
	$(CLI) fetch-dbs --profile $(PROFILE)

build-image: ## Build the complete toolchain image (binaries + Python + data)
	bash scripts/build-toolchain-image.sh

lint: ## ruff check + format --check
	uv run ruff check .
	uv run ruff format --check .

lint-fix: ## ruff --fix + format
	uv run ruff check --fix .
	uv run ruff format .

hooks: ## Enable .githooks for this clone
	git config core.hooksPath .githooks
	@chmod +x .githooks/* 2>/dev/null || true

status: ## Current version, tag, git state
	$(PYTHON) $(RELEASE) status

$(BUMP_PARTS):
	@:

bump: ## Bump VERSION + pyproject.toml: make bump patch|minor|major
	@part="$(filter $(BUMP_PARTS),$(MAKECMDGOALS))"; \
	if [ -z "$$part" ]; then \
		echo "usage: make bump patch|minor|major" >&2; \
		exit 1; \
	fi; \
	$(PYTHON) $(RELEASE) bump $$part

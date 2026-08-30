# AVE — shared Makefile verbs.
# The demo money-shot (see README "Quick start") is expressed here so the terminal
# story matches the docs: break -> eradicate -> scoreboard.

PYTHON ?= python3

.DEFAULT_GOAL := help

.PHONY: help setup lint typecheck test check eval run break eradicate scoreboard clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Install AVE + dev tooling into the current environment
	$(PYTHON) -m pip install -e ".[dev]"

lint: ## Lint with ruff
	ruff check src evals

typecheck: ## Strict type-check with mypy
	mypy

test: ## Run the test suite if tests/ is present locally
	@if [ -d tests ]; then pytest; else echo "skip pytest: tests/ is not in this tree"; fi

check: lint typecheck test ## Lint + typecheck + tests (the CI gate)

eval: ## Run promptfoo eval suites against the real graph
	cd evals && npx --yes promptfoo eval -c promptfooconfig.yaml

run: ## Walk the seven-phase graph on one seeded instance, write artifacts
	$(PYTHON) -m ave.cli run

break: ## Report the semantic flaws already seeded in the target (demo step 1)
	$(PYTHON) -m ave.cli break

eradicate: ## Demo: break -> auto-approved run -> PR bundle (HITL does not pause)
	$(PYTHON) -m ave.cli eradicate

scoreboard: ## Regenerate the results table from run records (demo step 4)
	$(PYTHON) -m ave.cli scoreboard

clean: ## Remove caches and build artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info htmlcov .coverage

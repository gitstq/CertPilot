.PHONY: help install dev test lint clean build

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install certpilot in development mode
	pip install -e .

dev: ## Install with development dependencies
	pip install -e ".[dev]"

test: ## Run tests
	pytest tests/ -v --cov=certpilot --cov-report=term-missing

lint: ## Run linters
	flake8 certpilot/
	black --check certpilot/
	mypy certpilot/

format: ## Format code with black
	black certpilot/

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

build: ## Build the package
	python -m build

publish: ## Publish to PyPI
	twine upload dist/*

run: ## Run certpilot CLI
	python -m certpilot.cli

version: ## Show version
	python -c "from certpilot import __version__; print(__version__)"

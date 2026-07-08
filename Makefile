.PHONY: help install dev build clean lint test typecheck publish publish-test

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install stryx in the current environment
	pip install -e .

dev:  ## Install stryx in development mode with all dev dependencies
	pip install -e ".[dev,xml]"

build:  ## Build sdist and wheel distributions
	pip install build
	python -m build
	@echo ""
	@echo "Packages built in dist/"
	@ls -la dist/

clean:  ## Clean build artifacts
	rm -rf dist/ build/ *.egg-info stryx/*.egg-info
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -rf htmlcov/ .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

lint:  ## Run linting (ruff)
	pip install ruff
	python -m ruff check stryx/ --fix
	python -m ruff format stryx/

test:  ## Run tests
	pip install -e ".[dev]"
	python -m pytest tests/ -v --tb=short

typecheck:  ## Run type checking
	pip install mypy
	python -m mypy stryx/ --ignore-missing-imports

publish:  ## Publish to PyPI (requires twine)
	pip install twine
	@echo "Building package..."
	python -m build
	@echo "Uploading to PyPI..."
	twine upload dist/*

publish-test:  ## Publish to TestPyPI (requires twine)
	pip install twine
	@echo "Building package..."
	python -m build
	@echo "Uploading to TestPyPI..."
	twine upload --repository testpypi dist/*

check:  ## Verify the package is well-formed
	pip install twine build
	python -m build
	twine check dist/*
	@echo ""
	@echo "Package verification passed!"

version:  ## Show current version
	@python -c "import stryx; print(f'STRYX v{stryx.__version__}')"

quick-test:  ## Quick smoke test - verify imports and CLI
	@echo "=== Import Check ==="
	@python -c "import stryx; print(f'STRYX v{stryx.__version__} imported OK')"
	@echo ""
	@echo "=== CLI Check ==="
	@python -m stryx --help

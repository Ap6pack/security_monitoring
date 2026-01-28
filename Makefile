.PHONY: help install install-dev clean lint format type-check test test-unit test-integration coverage run init-db docs

help:
	@echo "Security Scanner - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install          Install production dependencies"
	@echo "  make install-dev      Install development dependencies"
	@echo "  make init-db          Initialize database"
	@echo ""
	@echo "Development:"
	@echo "  make format           Format code with black"
	@echo "  make lint             Lint code with ruff"
	@echo "  make type-check       Type check with mypy"
	@echo "  make test             Run all tests"
	@echo "  make test-unit        Run unit tests only"
	@echo "  make test-integration Run integration tests only"
	@echo "  make coverage         Generate coverage report"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean            Remove build artifacts and cache"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs             Build documentation"
	@echo ""
	@echo "Running:"
	@echo "  make run              Run scanner with default config"

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements-dev.txt
	pip install -e .

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	find . -type f -name '*.coverage' -delete

format:
	black src/ tests/

lint:
	ruff check src/ tests/

lint-fix:
	ruff check --fix src/ tests/

type-check:
	mypy src/

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v -m unit

test-integration:
	pytest tests/integration/ -v -m integration

coverage:
	pytest tests/ --cov=security_scanner --cov-report=html --cov-report=term
	@echo "Coverage report generated in htmlcov/index.html"

init-db:
	python -c "from security_scanner.storage.database import DatabaseManager; import asyncio; asyncio.run(DatabaseManager('data/security_scanner.db').initialize())"

docs:
	mkdocs build

docs-serve:
	mkdocs serve

run:
	security-scanner scan --domains config/domains.yaml

run-test:
	security-scanner scan-domain example.com --verbose

validate:
	@echo "Running all validation checks..."
	@make format
	@make lint
	@make type-check
	@make test
	@echo "All checks passed!"

setup-dev: install-dev init-db
	@echo "Development environment setup complete!"
	@echo "Create your .env file from .env.example"

.DEFAULT_GOAL := help

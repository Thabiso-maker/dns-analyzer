# ==============================================================================
# DNS SECURITY ANALYZER — MAKEFILE
# ==============================================================================
# Usage: make <target>
# Run `make help` to see all available commands.
# ==============================================================================

.DEFAULT_GOAL := help
.PHONY: help install install-dev run run-dev run-worker lint format typecheck \
        test test-unit test-integration test-e2e test-cov \
        db-init db-migrate db-upgrade db-downgrade db-reset \
        docker-build docker-up docker-down docker-logs docker-shell \
        clean clean-all generate-key seed

# Colors for terminal output
CYAN  := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RESET := \033[0m

# ==============================================================================
# HELP
# ==============================================================================

help: ## Show this help message
	@echo ""
	@echo "  DNS Security Analyzer — Available Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-25s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# ==============================================================================
# INSTALLATION
# ==============================================================================

install: ## Install production dependencies
	@echo "$(GREEN)Installing production dependencies...$(RESET)"
	pip install poetry
	poetry install --only main

install-dev: ## Install all dependencies including dev tools
	@echo "$(GREEN)Installing all dependencies (including dev)...$(RESET)"
	pip install poetry
	poetry install
	poetry run pre-commit install
	@echo "$(GREEN)Done. Run 'make run-dev' to start the development server.$(RESET)"

# ==============================================================================
# RUNNING THE APPLICATION
# ==============================================================================

run: ## Run the production server
	@echo "$(GREEN)Starting production server...$(RESET)"
	poetry run uvicorn src.dns_analyzer.api.app:create_app \
		--host $${SERVER_HOST:-0.0.0.0} \
		--port $${SERVER_PORT:-8000} \
		--workers $${SERVER_WORKERS:-4} \
		--factory

run-dev: ## Run the development server with hot reload
	@echo "$(GREEN)Starting development server with hot reload...$(RESET)"
	poetry run uvicorn src.dns_analyzer.api.app:create_app \
		--host 0.0.0.0 \
		--port 8000 \
		--reload \
		--reload-dir src \
		--factory \
		--log-level debug

run-worker: ## Run the ARQ background job worker
	@echo "$(GREEN)Starting background job worker...$(RESET)"
	poetry run arq src.dns_analyzer.scheduler.job_queue.WorkerSettings

run-cli: ## Run the CLI tool (usage: make run-cli ARGS="scan google.com")
	poetry run dns-analyzer $(ARGS)

# ==============================================================================
# CODE QUALITY
# ==============================================================================

lint: ## Run linter (ruff)
	@echo "$(CYAN)Running ruff linter...$(RESET)"
	poetry run ruff check src cli tests

format: ## Auto-format code (black + ruff --fix)
	@echo "$(CYAN)Formatting code...$(RESET)"
	poetry run black src cli tests
	poetry run ruff check --fix src cli tests
	@echo "$(GREEN)Formatting complete.$(RESET)"

format-check: ## Check formatting without making changes (for CI)
	poetry run black --check src cli tests
	poetry run ruff check src cli tests

typecheck: ## Run static type checker (mypy)
	@echo "$(CYAN)Running mypy type checker...$(RESET)"
	poetry run mypy src cli

check: lint typecheck ## Run all code quality checks (lint + typecheck)

pre-commit: ## Run all pre-commit hooks manually
	poetry run pre-commit run --all-files

# ==============================================================================
# TESTING
# ==============================================================================

test: ## Run all tests
	@echo "$(CYAN)Running all tests...$(RESET)"
	poetry run pytest

test-unit: ## Run unit tests only (fast, no external deps)
	@echo "$(CYAN)Running unit tests...$(RESET)"
	poetry run pytest tests/unit -m unit -v

test-integration: ## Run integration tests (requires DB + Redis)
	@echo "$(CYAN)Running integration tests...$(RESET)"
	poetry run pytest tests/integration -m integration -v

test-e2e: ## Run end-to-end tests (requires full stack)
	@echo "$(CYAN)Running e2e tests...$(RESET)"
	poetry run pytest tests/e2e -m e2e -v

test-cov: ## Run tests with HTML coverage report
	@echo "$(CYAN)Running tests with coverage...$(RESET)"
	poetry run pytest --cov=src/dns_analyzer --cov-report=html
	@echo "$(GREEN)Coverage report: htmlcov/index.html$(RESET)"

test-fast: ## Run tests without coverage (faster)
	poetry run pytest --no-cov -x

test-watch: ## Run tests in watch mode (re-run on file changes)
	poetry run pytest-watch -- --no-cov tests/unit

# ==============================================================================
# DATABASE
# ==============================================================================

db-init: ## Initialize Alembic migrations (first time only)
	@echo "$(CYAN)Initializing Alembic...$(RESET)"
	poetry run alembic init src/dns_analyzer/database/migrations

db-migrate: ## Create a new migration (usage: make db-migrate MSG="add users table")
	@echo "$(CYAN)Creating migration: $(MSG)$(RESET)"
	poetry run alembic revision --autogenerate -m "$(MSG)"

db-upgrade: ## Apply all pending migrations
	@echo "$(CYAN)Applying database migrations...$(RESET)"
	poetry run alembic upgrade head

db-downgrade: ## Roll back the last migration
	@echo "$(YELLOW)Rolling back last migration...$(RESET)"
	poetry run alembic downgrade -1

db-reset: ## Drop and recreate the database (DESTRUCTIVE)
	@echo "$(YELLOW)WARNING: This will destroy all data. Press Ctrl+C to cancel.$(RESET)"
	@sleep 3
	poetry run alembic downgrade base
	poetry run alembic upgrade head
	poetry run python scripts/seed_db.py
	@echo "$(GREEN)Database reset complete.$(RESET)"

db-history: ## Show migration history
	poetry run alembic history --verbose

# ==============================================================================
# DOCKER
# ==============================================================================

docker-build: ## Build the Docker image
	@echo "$(CYAN)Building Docker image...$(RESET)"
	docker build -f infra/docker/Dockerfile -t dns-analyzer:latest .

docker-build-dev: ## Build the development Docker image
	docker build -f infra/docker/Dockerfile.dev -t dns-analyzer:dev .

docker-up: ## Start all services (app + postgres + redis)
	@echo "$(GREEN)Starting all services...$(RESET)"
	docker compose -f infra/docker-compose.yml up -d
	@echo "$(GREEN)Services started. API at http://localhost:8000$(RESET)"

docker-up-dev: ## Start dev stack with hot reload
	docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up

docker-down: ## Stop all services
	docker compose -f infra/docker-compose.yml down

docker-down-volumes: ## Stop all services and delete volumes (DESTRUCTIVE)
	docker compose -f infra/docker-compose.yml down -v

docker-logs: ## Tail logs for all services
	docker compose -f infra/docker-compose.yml logs -f

docker-logs-app: ## Tail logs for the app service only
	docker compose -f infra/docker-compose.yml logs -f app

docker-shell: ## Open a shell in the running app container
	docker compose -f infra/docker-compose.yml exec app /bin/bash

docker-ps: ## Show running containers
	docker compose -f infra/docker-compose.yml ps

# ==============================================================================
# UTILITIES
# ==============================================================================

generate-key: ## Generate a secure random API key
	@poetry run python scripts/generate_api_key.py

seed: ## Seed the database with sample data
	@echo "$(CYAN)Seeding database...$(RESET)"
	poetry run python scripts/seed_db.py

scan: ## Run a quick scan (usage: make scan DOMAIN=google.com)
	@poetry run dns-analyzer scan $(DOMAIN)

# ==============================================================================
# CLEANUP
# ==============================================================================

clean: ## Remove Python cache files
	@echo "$(CYAN)Cleaning cache files...$(RESET)"
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete
	@echo "$(GREEN)Clean complete.$(RESET)"

clean-all: clean ## Remove all build artifacts including venv
	rm -rf dist/ build/ *.egg-info/
	rm -rf venv/ .venv/
	@echo "$(GREEN)Full clean complete. Run 'make install-dev' to reinstall.$(RESET)"
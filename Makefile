.PHONY: install sync format lint test clean check format-check lint-check

sync:
	uv sync

install:
	uv tool install .

format:
	uv run ruff format .

lint:
	uv run ruff check --fix .
	uv run mypy .

format-check:
	@echo "Checking formatting..."
	uv run ruff format --check .

lint-check:
	@echo "Linting..."
	uv run ruff check --no-fix .
	@echo "Type checking..."
	uv run mypy .

test:
	uv run pytest -v

check: format-check lint-check test

clean:
	rm -rf .ruff_cache .mypy_cache .pytest_cache
	find . -name "__pycache__" -type d -exec rm -rf {} +
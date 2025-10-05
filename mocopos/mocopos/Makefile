.PHONY: run test lint fmt precommit

run:
	uv run mcp-scan https://github.com/octocat/Hello-World

test:
	uv run pytest -q

fmt:
	uv run ruff format .

lint:
	uv run ruff check .

precommit:
	pre-commit install

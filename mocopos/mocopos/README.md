# MCP Scanner (MVP)

Terminal tool that scans a GitHub repository for potential issues (secrets, basic heuristics) and outputs:
- a concise terminal summary, and
- a JSON report validated against a schema.

## Quickstart

```bash
uv venv && source .venv/bin/activate
uv sync
cp .env.example .env  # add your GitHub token
uv run mcp-scan https://github.com/owner/repo

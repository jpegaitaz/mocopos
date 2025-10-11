# MCP Scanner (MVP)

Terminal tool that scans GitHub repositories for **secrets** and **suspicious patterns** (MCP-aware heuristics), then outputs:

- a concise **terminal summary**, and  
- a **JSON report** validated against a schema.

It also includes `mcp-scan-search` to discover MCP servers on GitHub, batch scan them (with throttling), and print a leaderboard.

---

## Features

- **Scanners**: `secrets`, `entropy_secrets`, `static_risk`, `taint_risk`, `deps_audit`, `github_actions` (+ optional `yara` if installed)
- **MCP-aware checks**: command exec sinks, file ops outside safe root, off-allowlist network egress, risky npm lifecycle, unpinned GH Actions, secrets exfil in CI
- **Schema-validated reports** (`schemas/report.schema.json`)
- **Batch scanning / discovery** with rate-limit friendly batching & retries
- **Archive mode**: scans via ZIP download to avoid burning REST API quota
- **Exit codes** for CI gates: `0=Safe`, `1=Potential Threat`, `2=Threat`

---

## Requirements

- Python 3.11+
- [uv](https://github.com/astral-sh/uv)
- A GitHub token with public repo read (fine to use `secrets.GITHUB_TOKEN` in CI)

---

## Usage
- **Scan a single repository**
uv run mcp-scan https://github.com/<owner>/<repo> [--ref <branch-or-tag>] \
  [--include "globs,**/*.py"] [--exclude "globs,**/*.md"] [--out ./report.json]

- **Examples**
# ^default branch
uv run mcp-scan https://github.com/octocat/Hello-World

# pin to branch or tag
uv run mcp-scan https://github.com/github/github-mcp-server --ref main

# focus on code, skip docs
uv run mcp-scan https://github.com/<owner>/<repo> --include "**/*.py,**/*.ts" --exclude "**/*.md"

# custom output path
uv run mcp-scan https://github.com/<owner>/<repo> --out ./report.json

Exit codes (CI-friendly): 0=Safe, 1=Potential Threat, 2=Threat.

# Discover & batch scan many repos

uv run mcp-scan-search \
  --query "mcp server" \
  --pages 2 --per-page 50 --page-start 1 \
  --print-repos \
  --batch-size 6 --workers 3 --sleep-seconds 8 \
  --on-403-sleep 90 --retry-403 2 \
  --out ./scan_search.json

Paging: --pages, --per-page, --page-start

List only: --list-only (no scans), --save-repos ./repos.json

Resume/skip: --resume N (skip first N of current list), --skip-from ./scan_search.json (don’t re-scan already seen repos)

From saved list: --from-file ./repos.json

Batch politeness: --batch-size, --workers, --sleep-seconds, --on-403-sleep, --retry-403

# Examples

# Build a repo list without scanning
uv run mcp-scan-search -q "mcp server language:Python" \
  --pages 10 --per-page 100 --list-only --save-repos ./repos_py.json

# Scan from saved list with throttling
uv run mcp-scan-search --from-file ./repos_py.json \
  --batch-size 6 --workers 3 --sleep-seconds 10 \
  --on-403-sleep 120 --retry-403 2 \
  --out ./scan_search_py.json

# Continue from the next pages and skip anything already scanned
uv run mcp-scan-search -q "mcp server" --page-start 1 --pages 5 --per-page 50 \
  --skip-from ./scan_search.json \
  --batch-size 6 --workers 3 --sleep-seconds 8 \
  --out ./scan_search_part2.json

## License 

MIT

Copyright © 2025 DarkMatter

---

## Quickstart

```bash
uv venv && source .venv/bin/activate
uv sync
cp .env.example .env  # add your GitHub token
uv run mcp-scan https://github.com/owner/repo

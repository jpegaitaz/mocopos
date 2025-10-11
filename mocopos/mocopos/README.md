# MCP Scanner (MVP)

Terminal tool that scans GitHub repositories for **secrets** and **suspicious patterns** (MCP-aware heuristics), then outputs:

- a concise **terminal summary**
- a **JSON/JSONL report** validated against a schema
- optional **corporate-grade reports** (Markdown and PDF), including a **single, consolidated portfolio report**

It also includes `mcp-scan-search` to discover MCP servers on GitHub, batch scan them (with throttling), and print a leaderboard.

---

## Features

- **Scanners**: `secrets`, `entropy_secrets`, `static_risk`, `taint_risk`, `deps_audit`, `github_actions` (+ optional `yara` if installed)
- **MCP-aware checks**: command exec sinks, file ops outside safe root, off-allowlist network egress, risky npm lifecycle, unpinned GH Actions, CI exfil patterns
- **Schema-validated reports** (`schemas/report.schema.json`)
- **Batch scanning / discovery** with rate-limit-friendly batching & retries
- **Archive mode**: scan via ZIP download to reduce REST quota
- **Exit codes** for CI gates: `0=Safe`, `1=Potential Threat`, `2=Threat`
- **Reporting**:
  - Per-repo Markdown (and optional PDF)
  - **Consolidated portfolio report** across many repos (Markdown & single PDF)
  - Session-stamped filenames: `YYYYMMDD_HHMMSSZ-<SESSION>__BATCH_SUMMARY.(md|pdf)`

---

## Requirements

- Python **3.11+**
- [uv](https://github.com/astral-sh/uv)
- macOS/Linux with system libs for PDF (if you want PDF output):
  - macOS (Homebrew): `brew install pango cairo gdk-pixbuf libffi pkg-config`
- A GitHub token with public repo read (fine to use `secrets.GITHUB_TOKEN` in CI)

---

## Usage
### Scan a single repository

```bash
# default branch
uv run mcp-scan https://github.com/octocat/Hello-World

# pin to branch or tag
uv run mcp-scan https://github.com/github/github-mcp-server --ref main

# focus on code, skip docs
uv run mcp-scan https://github.com/<owner>/<repo> \
  --include "**/*.py,**/*.ts" --exclude "**/*.md"

# custom output path
uv run mcp-scan https://github.com/<owner>/<repo> --out ./report.json

```bash

---

## Install / Quickstart

```bash
uv venv && source .venv/bin/activate
uv sync
cp .env.example .env    # add your GitHub token

```bash


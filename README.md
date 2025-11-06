# MOCOPOS (Model Context Protocol Scanner)

```text

M   M  OOO   CCCC  OOO  PPPP   OOO   SSS 
MM MM O   O C     O   O P   P O   O S    
M M M O   O C     O   O PPPP  O   O  SSS 
M   M O   O C     O   O P     O   O     S
M   M  OOO   CCCC  OOO  P      OOO   SSS 

    MODEL CONTEXT PROTOCOL SCANNER
             BY DarkMatter

```

MOCOPOS is a terminal-first toolkit for auditing GitHub repositories for secrets, high-entropy blobs, and risky Model Context Protocol (MCP) behaviours. It combines multiple heuristics into a single workflow, produces machine-readable results, and can batch-scan entire portfolios.

---

## Highlights
- Multi-engine scanners (`secrets`, `entropy_secrets`, `static_risk`, `taint_risk`, `deps_audit`, `github_actions`, optional `yara`) with MCP-aware fingerprints.
- Schema-validated JSON/JSONL output (`schemas/report.schema.json`) plus optional Markdown/PDF reports suitable for compliance stakeholders.
- CI-friendly exit codes (`0` safe, `1` potential threat, `2` threat) for gating pull requests or releases.
- Batch discovery (`mcp-scan-search`) that finds GitHub MCP servers, throttles API usage, and aggregates a leaderboard.
- Archive-mode downloads to conserve GitHub API quota while still scanning entire repositories.

## Prerequisites
- Python 3.11 or newer
- [uv](https://github.com/astral-sh/uv) for dependency management
- macOS or Linux with PDF native libraries when rendering PDFs (e.g. `brew install pango cairo gdk-pixbuf libffi pkg-config` on macOS)
- A GitHub token with read access to the repositories you plan to scan (`GITHUB_TOKEN` or `GITHUB_TOKENS`)

## Installation
```bash
git clone https://github.com/<owner>/mocopos.git
cd mocopos
uv venv
source .venv/bin/activate
uv sync
```

Create an `.env` file (or export directly in your shell) with the credentials and optional pacing settings:

```bash
echo "GITHUB_TOKEN=ghp_your_token" >> .env
# Optional: rotate between multiple tokens to smooth rate limits
echo "GITHUB_TOKENS=token_one,token_two" >> .env
# Optional: fine-tune client pacing (seconds between requests)
echo "MOCOPOS_CORE_RPS=1.5" >> .env
```

Run `source .venv/bin/activate && uv run <command>` each time you use the tool.

## Command Overview

### `mcp-scan`
Scan a single repository (default branch unless pinned). The workflow fetches the code, runs every configured scanner, validates the JSON against `report.schema.json`, prints a Rich terminal summary, and writes the report to disk.

```bash
uv run mcp-scan https://github.com/octocat/Hello-World
uv run mcp-scan https://github.com/github/github-mcp-server --ref main
uv run mcp-scan https://github.com/<owner>/<repo> \
  --include "src/**,**/*.py" \
  --exclude "**/*.md"
uv run mcp-scan https://github.com/<owner>/<repo> --out ./reports/hello-world.json
```

Core options:
- `--ref`: Branch or tag to scan (defaults to the repository default branch).
- `--out`: Path for the JSON report; defaults to `report.output_path` in `configs/settings.toml`.
- `--include` / `--exclude`: Comma-separated glob overrides that supplement or bypass `configs/settings.toml`.
- `--help`: Explore the full set of flags.

Exit codes:
- `0`: Safe — no threats detected.
- `1`: Potential Threat — findings require review.
- `2`: Threat — clear risk detected (recommended to block CI).

### `mcp-scan-search`
Discover and optionally batch-scan repositories that match a GitHub search query (defaults to “mcp server”). Useful for fleet monitoring and leaderboards.

```bash
uv run mcp-scan-search --query "mcp server" --pages 3 --per-page 20 --print-repos
uv run mcp-scan-search --from-file repos.json --batch-size 5 --workers 2 --sleep-seconds 3
uv run mcp-scan-search --query "org:my-company MCP" --list-only --save-repos discovered.json
```

Notable flags:
- `--pages`, `--per-page`, `--page-start`: Control GitHub search pagination.
- `--min-stars`, `--max-results`, `--resume`: Filter and resume large hunts.
- `--include`, `--exclude`: Same glob behaviour as `mcp-scan`.
- `--batch-size`, `--workers`, `--per-repo-delay`: Tune throughput versus rate-limit pressure.
- `--out`: Persist a combined JSON summary for the batch.
- `--skip-from` / `--from-file`: Reuse previously discovered repositories.

`mcp-scan-search` shows progress bars, rotates tokens automatically, and respects the `--rate-floor` guard before each batch.

### `mocopos-llm-chat`
Launch an interactive CLI that proxies prompts through the LLM interpreter used for report generation:

```bash
uv run mocopos-llm-chat --model gpt-4o-mini
```

## Reports
- JSON: Written to the path derived from `--out` or `configs/settings.toml`. Validated against `schemas/report.schema.json`.
- JSONL: When scanning batches, append-only logs live alongside per-repo reports.
- Markdown / PDF: Install optional extras with `uv sync --extra report` (or add the `report` feature to your environment). Reports land in `reports/` using session-stamped filenames such as `YYYYMMDD_HHMMSSZ-<SESSION>__BATCH_SUMMARY.md`.
- Terminal: Rich summary highlights total findings, classification, and top offenders.

## Configuration
Configuration lives in `configs/`:
- `settings.toml`: GitHub API base, default output path, ignore/allow globs.
- `scanners.toml`: Enable/disable individual scanners and tweak thresholds.
- `policies.yaml`: Corporate reporting templates and risk policies.
- `logging.toml`: Rich + file logging configuration.
- `.mocoposignore`: Repo-level overrides for directories/files to skip.

Modify these files in your fork or mount alternative paths via environment variables when running in CI/CD.

## Project Layout
- `src/mocopos/cli/`: Command-line entry points (`mcp-scan`, `mcp-scan-search`, `mocopos-llm-chat`).
- `src/mocopos/core/`: Session orchestration, workflow engine, and result aggregation.
- `src/mocopos/scanning/`: Individual scanners (secrets, taint, static risk, YARA, etc.).
- `schemas/`: JSON Schema definitions for produced reports.
- `prompts/`: Prompt templates used for Markdown/PDF synthesis.
- `tests/`: Pytest suite with fixtures covering scanner behaviours.

## Development
```bash
uv run pytest -q          # run tests
uv run ruff check .       # lint
uv run ruff format .      # auto-format
make run                  # smoke test (scans Hello-World)
```

Before opening a PR, ensure lint/tests pass and consider enabling the `precommit` target (`make precommit`) to install hooks.

## Troubleshooting
- **Missing credentials**: Provide at least one `GITHUB_TOKEN`. Multiple tokens in `GITHUB_TOKENS` are recommended for batch scanning.
- **Rate limiting**: Adjust `MOCOPOS_CORE_RPS`, `MOCOPOS_SEARCH_RPS`, and `MOCOPOS_BUCKET_CAP` via environment variables.
- **PDF rendering fails**: Install the optional `report` extras and system packages listed above.
- **Large repositories**: Tune `scanner.max_bytes_per_file` and ignore lists in `configs/settings.toml` to focus on relevant files.


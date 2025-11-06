from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv
from rich.console import Console
from jsonschema import validate, ValidationError

from mocopos.config.loader import Settings
from mocopos.core.session import Session
from mocopos.core.workflow import Workflow
from mocopos.reporting.json_reporter import JsonReporter
from mocopos.reporting.terminal_reporter import TerminalReporter
from mocopos.connectors.github_client import GithubClient

console = Console()

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_csv_globs(val: Optional[str]) -> list[str]:
    if not val:
        return []
    return [v.strip() for v in val.split(",") if v.strip()]

@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.argument("repo_url", metavar="REPO_URL")
@click.option("--ref", type=str, default=None, help="Branch or tag (defaults to repo default branch)")
@click.option("--out", "out_path", type=click.Path(dir_okay=False, writable=True, path_type=Path),
              default=None, help="Path to write the JSON report (overrides config)")
@click.option("--include", "include_globs", type=str, default=None,
              help="Comma-separated globs to FORCE include (e.g., 'src/**,**/*.py').")
@click.option("--exclude", "exclude_globs", type=str, default=None,
              help="Comma-separated globs to exclude (overrides config ignores).")
def main(repo_url: str, ref: Optional[str], out_path: Optional[Path], include_globs: Optional[str], exclude_globs: Optional[str]) -> None:
    """
    Example:
      uv run mcp-scan https://github.com/octocat/Hello-World --out ./report.json
      uv run mcp-scan <repo> --include "src/**,**/*.py" --exclude "**/*.md"
    """
    load_dotenv()
    settings = Settings.load()

    # Show rate before/after to catch unexpected bursts
    gh = GithubClient(api_base=settings.github.api_base)
    try:
        rate = gh._request("GET", f"{gh.api_base}/rate_limit", tries=1).json().get("resources", {})
        console.print(f"[dim]Rate before: core={rate.get('core',{}).get('remaining','?')}/{rate.get('core',{}).get('limit','?')}[/dim]")
    except Exception:
        pass

    session = Session(session_id=str(uuid.uuid4()), started_at=_utc_now_iso())
    wf = Workflow(settings=settings, session=session)
    result = wf.run(
        repo_url=repo_url,
        ref=ref,
        include_globs=parse_csv_globs(include_globs),
        exclude_globs=parse_csv_globs(exclude_globs),
    )

    schema_path = Path(__file__).resolve().parents[3] / "schemas" / "report.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        validate(instance=result, schema=schema)
    except ValidationError as e:
        console.print(f"[red]Report validation failed:[/red] {e.message}")
        sys.exit(2)

    output_path = out_path or Path(settings.report.output_path)
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    TerminalReporter.print_summary(result)
    JsonReporter.print_hint(output_path)

    try:
        rate = gh._request("GET", f"{gh.api_base}/rate_limit", tries=1).json().get("resources", {})
        console.print(f"[dim]Rate after : core={rate.get('core',{}).get('remaining','?')}/{rate.get('core',{}).get('limit','?')}[/dim]")
    except Exception:
        pass

    code_map = {"Safe": 0, "Potential Threat": 1, "Threat": 2}
    sys.exit(code_map.get(result.get("classification", "Potential Threat"), 1))

if __name__ == "__main__":
    main()


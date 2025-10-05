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

console = Console()

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.argument("repo_url", metavar="REPO_URL")
@click.option("--ref", type=str, default=None, help="Branch or tag (defaults to repo default branch)")
@click.option("--out", "out_path", type=click.Path(dir_okay=False, writable=True, path_type=Path),
              default=None, help="Path to write the JSON report (overrides config)")
def main(repo_url: str, ref: Optional[str], out_path: Optional[Path]) -> None:
    """
    Example:
      uv run mcp-scan https://github.com/octocat/Hello-World --out ./report.json
    """
    load_dotenv()
    settings = Settings.load()

    session = Session(session_id=str(uuid.uuid4()), started_at=_utc_now_iso())
    wf = Workflow(settings=settings, session=session)
    result = wf.run(repo_url=repo_url, ref=ref)

    # Validate JSON against schema
    schema_path = Path(__file__).resolve().parents[3] / "schemas" / "report.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        validate(instance=result, schema=schema)
    except ValidationError as e:
        console.print(f"[red]Report validation failed:[/red] {e.message}")
        sys.exit(2)

    # Save JSON (CLI --out takes precedence)
    output_path = out_path or Path(settings.report.output_path)
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    TerminalReporter.print_summary(result)
    JsonReporter.print_hint(output_path)

if __name__ == "__main__":
    main()

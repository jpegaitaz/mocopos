from __future__ import annotations
from typing import Dict, Any
from rich.console import Console
from rich.table import Table

console = Console()

class TerminalReporter:
    @staticmethod
    def print_summary(report: Dict[str, Any]) -> None:
        console.rule("[bold]Mocopos Scanner[/bold]")
        console.print(f"[bold]Session:[/bold] {report['session_id']}")
        console.print(f"[bold]Repo:[/bold] {report['repo']['owner']}/{report['repo']['name']} @ {report['repo']['ref']} ({report['repo']['commit'][:7]})")
        console.print(f"[bold]Scanned files:[/bold] {report['stats']['files_scanned']}  |  [bold]Bytes:[/bold] {report['stats']['bytes_scanned']}")
        console.print(f"[bold]Classification:[/bold] {report['classification']}")
        console.print(f"[italic]{report['summary']}[/italic]")
        if report["findings"]:
            table = Table(title="Findings (top 10)")
            table.add_column("Path", overflow="fold")
            table.add_column("Rule")
            table.add_column("Severity")
            table.add_column("Reason", overflow="fold")
            for f in report["findings"][:10]:
                table.add_row(f["path"], f["rule_id"], f["severity"], f["reason"])
            console.print(table)
        console.rule()

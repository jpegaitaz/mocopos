from __future__ import annotations
from pathlib import Path
from rich.console import Console

console = Console()

class JsonReporter:
    @staticmethod
    def print_hint(path: Path):
        console.print(f"[green]JSON report saved to:[/green] {path.resolve()}")

from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # py310
    import tomli as tomllib  # type: ignore

@dataclass
class GithubConfig:
    api_base: str = "https://api.github.com"

@dataclass
class ReportConfig:
    output_path: str = "report.json"

@dataclass
class ScannerConfig:
    max_bytes_per_file: int = 500_000
    ignore_globs: list[str] = field(default_factory=lambda: [
        "**/.git/**", "**/.github/**", "**/node_modules/**", "**/dist/**", "**/build/**",
        "**/.venv/**", "**/*.min.js", "**/*.min.css", "**/*.lock",
        "**/*.png", "**/*.jpg", "**/*.jpeg", "**/*.gif", "**/*.webp",
        "**/*.pdf", "**/*.zip", "**/*.tar", "**/*.tgz", "**/*.gz",
    ])

@dataclass
class Settings:
    github: GithubConfig
    report: ReportConfig
    scanner: ScannerConfig

    @staticmethod
    def load() -> "Settings":
        cfg_path = Path(__file__).resolve().parents[3] / "configs" / "settings.toml"
        data = {}
        if cfg_path.exists():
            with cfg_path.open("rb") as f:
                data = tomllib.load(f)

        gh = GithubConfig(
            api_base=os.getenv("GITHUB_API_BASE", data.get("github", {}).get("api_base", "https://api.github.com"))
        )
        rep = ReportConfig(
            output_path=data.get("report", {}).get("output_path", "report.json")
        )
        scn_section = data.get("scanner", {})
        scn = ScannerConfig(
            max_bytes_per_file=int(scn_section.get("max_bytes_per_file", 500_000)),
            ignore_globs=list(scn_section.get("ignore_globs", ScannerConfig().ignore_globs)),
        )
        return Settings(github=gh, report=rep, scanner=scn)

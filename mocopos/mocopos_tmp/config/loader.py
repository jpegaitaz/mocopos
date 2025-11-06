# src/mocopos/config/loader.py
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # py310
    import tomli as tomllib  # type: ignore


# -------- helpers --------

def _env_bool(name: str, default: bool) -> bool:
    """Parse typical truthy/falsey env values safely."""
    val = os.getenv(name)
    if val is None:
        return default
    v = val.strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        return True
    if v in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _dedup_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for g in items:
        g2 = g.strip()
        if not g2 or g2 in seen:
            continue
        seen.add(g2)
        out.append(g2)
    return out


def _read_ignore_file(path: Path) -> List[str]:
    """
    Read a '.mocoposignore' style file:
    - Strip whitespace
    - Skip empty lines and '#' comments
    """
    try:
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    globs: List[str] = []
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        globs.append(s)
    return globs


# -------- data classes --------

@dataclass
class GithubConfig:
    api_base: str = "https://api.github.com"
    # Prefer the zipball archive path (cheap quota + fewer REST calls)
    prefer_archive: bool = True


@dataclass
class ReportConfig:
    output_path: str = "report.json"


def _default_ignores() -> List[str]:
    """
    Sane, conservative defaults that avoid noisy/huge non-code artifacts.
    Extend via settings.toml `scanner.ignore_globs_extend` or env
    `MOCOPOS_SCANNER_IGNORE_GLOBS_EXTRA` (comma-separated), and/or a
    repo-local `.mocoposignore` file at the working directory root.
    """
    return [
        # VCS / CI
        "**/.git/**", "**/.github/**", "**/.gitlab/**", "**/.circleci/**",

        # Python caches / envs
        "**/__pycache__/**", "**/.mypy_cache/**", "**/.pytest_cache/**",
        "**/.cache/**", "**/.ruff_cache/**",
        "**/.venv/**", "**/venv/**", "**/.tox/**",

        # Node / vendored
        "**/node_modules/**", "**/vendor/**",

        # Build outputs / dist
        "**/dist/**", "**/build/**", "**/.next/**", "**/.vite/**", "**/out/**", "**/target/**",

        # Lockfiles & dependency metadata (often very large / high-entropy)
        "**/package-lock.json", "**/pnpm-lock.yaml", "**/yarn.lock", "**/*.lock",

        # Large/non-text/binary-ish assets
        "**/*.min.js", "**/*.min.css",
        "**/*.png", "**/*.jpg", "**/*.jpeg", "**/*.gif", "**/*.webp", "**/*.svg", "**/*.svgz",
        "**/*.ico", "**/*.icns",
        "**/*.pdf", "**/*.zip", "**/*.tar", "**/*.tgz", "**/*.gz", "**/*.xz", "**/*.7z",
        "**/*.bin", "**/*.exe", "**/*.dll", "**/*.so", "**/*.dylib",
        "**/*.mp4", "**/*.mov", "**/*.mp3", "**/*.wav",

        # Notebooks and big data blobs
        "**/*.ipynb",
        "**/fixtures/**", "**/fixture/**", "**/testdata/**", "**/tests/data/**",
        "**/samples/**", "**/sample_data/**",

        # Docs / sites (usually not code, very large trees)
        "**/docs/**", "**/website/**",

        # Coverage / reports / generated artifacts
        "**/coverage/**", "**/.coverage*", "**/htmlcov/**", "**/reports/**",
        "**/report/**", "**/artifacts/**",
    ]


@dataclass
class ScannerConfig:
    max_bytes_per_file: int = 500_000
    ignore_globs: list[str] = field(default_factory=_default_ignores)


@dataclass
class Settings:
    github: GithubConfig
    report: ReportConfig
    scanner: ScannerConfig

    @staticmethod
    def load() -> "Settings":
        # settings.toml location (project-root/configs/settings.toml)
        cfg_path = Path(__file__).resolve().parents[3] / "configs" / "settings.toml"
        data: dict = {}
        if cfg_path.exists():
            with cfg_path.open("rb") as f:
                data = tomllib.load(f)

        gh_section = data.get("github", {}) or {}
        rep_section = data.get("report", {}) or {}
        scn_section = data.get("scanner", {}) or {}

        # --- Github ---
        gh = GithubConfig(
            api_base=os.getenv(
                "GITHUB_API_BASE",
                gh_section.get("api_base", "https://api.github.com"),
            ),
            # Parse env robustly; fallback to TOML value, default True
            prefer_archive=_env_bool(
                "GITHUB_PREFER_ARCHIVE",
                bool(gh_section.get("prefer_archive", True)),
            ),
        )

        # --- Report (allow simple env override if desired) ---
        report_path_env = os.getenv("MOCOPOS_REPORT_PATH")
        rep = ReportConfig(
            output_path=(report_path_env or rep_section.get("output_path", "report.json"))
        )

        # --- Scanner (merge-friendly) ---
        defaults = _default_ignores()

        # Full replacement if user explicitly sets `scanner.ignore_globs`
        user_ignores = scn_section.get("ignore_globs")
        if user_ignores is not None:
            if not isinstance(user_ignores, list):
                raise TypeError("scanner.ignore_globs must be a list of glob strings")
            effective_ignores = [str(x) for x in user_ignores]
        else:
            # Start from defaults and extend
            effective_ignores = list(defaults)

            # Optional extension via TOML
            extra_toml = scn_section.get("ignore_globs_extend", [])
            if extra_toml:
                if not isinstance(extra_toml, list):
                    raise TypeError("scanner.ignore_globs_extend must be a list of glob strings")
                effective_ignores.extend([str(x) for x in extra_toml])

            # Optional extension via ENV (comma-separated)
            extra_env = os.getenv("MOCOPOS_SCANNER_IGNORE_GLOBS_EXTRA", "")
            if extra_env.strip():
                effective_ignores.extend([g.strip() for g in extra_env.split(",") if g.strip()])

            # Optional repo-local ignore file at CWD
            # Allows per-repo tuning without code/config changes.
            cwd_ignore = _read_ignore_file(Path.cwd() / ".mocoposignore")
            if cwd_ignore:
                effective_ignores.extend(cwd_ignore)

        # Deduplicate & normalize
        effective_ignores = _dedup_keep_order(effective_ignores)

        scn = ScannerConfig(
            max_bytes_per_file=int(scn_section.get("max_bytes_per_file", 500_000)),
            ignore_globs=effective_ignores,
        )

        return Settings(github=gh, report=rep, scanner=scn)

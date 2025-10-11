from __future__ import annotations
from fnmatch import fnmatch
from typing import List

from mocopos.core.result_types import Finding
from mocopos.scanning.secrets.detectors import SecretsDetector
from mocopos.scanning.secrets.entropy import EntropySecretsDetector
from mocopos.scanning.static.ast_rules import StaticRiskDetector
from mocopos.scanning.static.ast_taint import TaintRiskDetector
from mocopos.scanning.deps.audit import DepsAudit
from mocopos.scanning.ci.github_actions import GitHubActionsScanner
from mocopos.scanning.malware.yara_scan import YaraScanner  # optional, handled gracefully
from mocopos.connectors.github_client import GithubClient
from mocopos.utils.filetype import is_probably_binary

# Secondary “code-ish” extension guard (workflow also filters earlier)
_CODE_EXTS = {
    ".py", ".ts", ".tsx", ".js", ".jsx",
    ".go", ".rs", ".java", ".kt", ".swift", ".scala",
    ".c", ".cpp", ".h", ".hpp", ".cs",
    ".rb", ".php",
    ".sh", ".bash", ".zsh", ".ps1",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
}

# Common lockfiles that explode entropy/secret noise
_LOCKFILE_BASENAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "poetry.lock",
    "Cargo.lock",
    "composer.lock",
    "go.sum",
}

# Dependency manifest files worth auditing
_MANIFEST_OR_LOCK = _LOCKFILE_BASENAMES | {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Pipfile",
    "setup.cfg",
    "setup.py",
    "go.mod",
    "Cargo.toml",
    "composer.json",
    "Gemfile",
    "Gemfile.lock",
}

def _ext(path: str) -> str:
    p = path.lower().rsplit(".", 1)
    return f".{p[1]}" if len(p) == 2 else ""

def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


class ScannerRunner:
    def __init__(
        self,
        max_bytes: int,
        github: GithubClient,
        owner: str,
        name: str,
        ignore_globs: List[str] | None = None,
        include_globs: List[str] | None = None,
    ):
        self.max_bytes = max_bytes
        self.github = github
        self.owner = owner
        self.name = name
        self.ignore_globs = ignore_globs or []
        self.include_globs = include_globs or []

        self._scanners = [
            SecretsDetector(),
            EntropySecretsDetector(),
            StaticRiskDetector(),
            TaintRiskDetector(),
            DepsAudit(),
            GitHubActionsScanner(),
        ]
        # Add YARA if available
        try:
            self._scanners.append(YaraScanner())
        except Exception:
            pass

    def scanners_used(self) -> List[str]:
        return [s.name for s in self._scanners]

    def _matches_any(self, path: str, globs: List[str]) -> bool:
        return any(fnmatch(path, pat) for pat in globs)

    def _ignored(self, path: str) -> bool:
        # include globs take precedence
        if self.include_globs and self._matches_any(path, self.include_globs):
            return False
        return self._matches_any(path, self.ignore_globs)

    def _should_run_deps_audit(self, path: str) -> bool:
        return _basename(path) in _MANIFEST_OR_LOCK

    def _is_lockfile(self, path: str) -> bool:
        return _basename(path) in _LOCKFILE_BASENAMES

    def scan_file(self, path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []

        # SPECIAL CASE: always scan GitHub Actions workflow files for CI risks
        if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            for scanner in self._scanners:
                if scanner.name == "github_actions":
                    try:
                        findings.extend(scanner.scan(path, content))
                    except Exception:
                        pass
            return findings

        # Respect include/exclude
        if self._ignored(path):
            return findings

        # Basic guards
        if not content:
            return findings
        if len(content.encode("utf-8", errors="ignore")) > self.max_bytes:
            return findings
        if is_probably_binary(content):
            return findings

        # Secondary extension guard (helps if runner used standalone)
        if self.include_globs == []:
            # Only enforce when include_globs not explicitly set
            if _ext(path) and _ext(path) not in _CODE_EXTS and not self._should_run_deps_audit(path):
                return findings

        # If it's a lockfile, only run dependency audit (skip entropy/secrets noise)
        if self._is_lockfile(path):
            for scanner in self._scanners:
                if scanner.name == "deps_audit":
                    try:
                        findings.extend(scanner.scan(path, content))
                    except Exception:
                        pass
            return findings

        # For non-lock files: run all appropriate scanners
        for scanner in self._scanners:
            # CI scanner only on workflows (handled above)
            if scanner.name == "github_actions":
                continue
            # Only run dependency audit on manifests/lockfiles
            if scanner.name == "deps_audit" and not self._should_run_deps_audit(path):
                continue
            try:
                findings.extend(scanner.scan(path, content))
            except Exception:
                # Never let a single scanner crash the pipeline
                pass

        return findings

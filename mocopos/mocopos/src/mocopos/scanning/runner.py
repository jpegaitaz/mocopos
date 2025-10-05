from __future__ import annotations
from fnmatch import fnmatch
from typing import List

from mocopos.core.result_types import Finding
from mocopos.scanning.secrets.detectors import SecretsDetector
from mocopos.scanning.secrets.entropy import EntropySecretsDetector
from mocopos.scanning.static.ast_rules import StaticRiskDetector
from mocopos.scanning.deps.audit import DepsAudit
from mocopos.scanning.malware.yara_scan import YaraScanner
from mocopos.connectors.github_client import GithubClient
from mocopos.utils.filetype import is_probably_binary

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
            DepsAudit(),
        ]
        # Add YARA if available (no-op if lib or rules missing)
        try:
            self._scanners.append(YaraScanner())
        except Exception:
            pass

    def scanners_used(self) -> List[str]:
        return [s.name for s in self._scanners]

    def _matches_any(self, path: str, globs: List[str]) -> bool:
        return any(fnmatch(path, pat) for pat in globs)

    def _ignored(self, path: str) -> bool:
        # include globs take precedence: if included, do not ignore
        if self.include_globs and self._matches_any(path, self.include_globs):
            return False
        return self._matches_any(path, self.ignore_globs)

    def scan_file(self, path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []

        if self._ignored(path):
            return findings
        if not content:
            return findings
        if len(content.encode("utf-8", errors="ignore")) > self.max_bytes:
            return findings
        if is_probably_binary(content):
            return findings

        for scanner in self._scanners:
            findings.extend(scanner.scan(path, content))
        return findings

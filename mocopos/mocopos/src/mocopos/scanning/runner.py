from __future__ import annotations
from typing import List

from mocopos.core.result_types import Finding
from mocopos.scanning.secrets.detectors import SecretsDetector
from mocopos.scanning.static.ast_rules import StaticRiskDetector
from mocopos.scanning.deps.audit import DepsAudit
from mocopos.connectors.github_client import GithubClient

class ScannerRunner:
    def __init__(self, max_bytes: int, github: GithubClient, owner: str, name: str):
        self.max_bytes = max_bytes
        self.github = github
        self.owner = owner
        self.name = name
        self._scanners = [
            SecretsDetector(),
            StaticRiskDetector(),
            DepsAudit(),
        ]

    def scanners_used(self) -> List[str]:
        return [s.name for s in self._scanners]

    def scan_file(self, path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        if not content:
            return findings
        if len(content.encode("utf-8", errors="ignore")) > self.max_bytes:
            return findings
        for scanner in self._scanners:
            findings.extend(scanner.scan(path, content))
        return findings

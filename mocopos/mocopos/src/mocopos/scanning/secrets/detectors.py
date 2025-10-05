from __future__ import annotations

import re
from typing import List
from mocopos.core.result_types import Finding

MASK = "****redacted****"

SECRET_PATTERNS = [
    ("aws_access_key", "Looks like an AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "high"),
    ("aws_secret_key", "Looks like an AWS Secret Key", r"(?i)aws(.{0,20})?(secret|access).{0,3}[:=].{0,3}([A-Za-z0-9/+=]{40})", "critical"),
    ("gh_token", "Possible GitHub token", r"gh[pousr]_[A-Za-z0-9_]{30,}", "high"),
    ("generic_api_key", "Generic API Key pattern", r"(?i)(api[_-]?key|token)[\"'\\s:=]{1,6}[A-Za-z0-9_\\-]{16,}", "medium"),
    ("password_inline", "Hardcoded password", r"(?i)password\\s*[:=]\\s*['\"][^'\"\\s]{6,}['\"]", "high"),
]

ALLOWLIST_PATHS = [
    r"\.md$",
    r"\.txt$",
    r"LICENSE$",
    r"CHANGELOG",
]

class SecretsDetector:
    name = "secrets"

    def scan(self, path: str, content: str) -> List[Finding]:
        for pat in ALLOWLIST_PATHS:
            if re.search(pat, path):
                return self._light_scan(path, content)

        findings: List[Finding] = []
        for rule_id, desc, rx, sev in SECRET_PATTERNS:
            for m in re.finditer(rx, content):
                findings.append(Finding(
                    path=path,
                    scanner=self.name,
                    rule_id=rule_id,
                    severity=sev,
                    reason=desc,
                    evidence=self._mask(content, m)
                ))
        return findings

    def _light_scan(self, path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for rule_id, desc, rx, sev in SECRET_PATTERNS:
            if rule_id in {"gh_token", "aws_secret_key"}:
                for m in re.finditer(rx, content):
                    findings.append(Finding(
                        path=path,
                        scanner=self.name,
                        rule_id=rule_id,
                        severity=sev,
                        reason=desc,
                        evidence=self._mask(content, m)
                    ))
        return findings

    def _mask(self, text, match: re.Match) -> str:
        start, end = match.span()
        pre = text[max(0, start-6):start]
        post = text[end:min(len(text), end+6)]
        return f"{pre}{MASK}{post}"

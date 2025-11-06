# src/mocopos/scanning/secrets/detectors.py
from __future__ import annotations

import re
from typing import List, Tuple, Set

from mocopos.core.result_types import Finding
from .entropy import EntropySecretsDetector

MASK = "****redacted****"

# Precompile secret patterns
_SECRET_PATTERNS = [
    ("aws_access_key", "Looks like an AWS Access Key ID", r"\bAKIA[0-9A-Z]{16}\b", "high"),
    ("aws_secret_key", "Looks like an AWS Secret Key",
     r"(?i)\baws(.{0,20})?(secret|access)\b.{0,3}[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", "critical"),
    ("gh_token", "Possible GitHub token", r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b", "high"),
    # Require an assignment + quoted value; avoid matching identifiers alone; avoid ${...} template interpolation
    ("generic_api_key", "Generic API Key pattern",
     r"(?i)\b(api[_-]?key|token|bearer)\b[^:<=\n]{0,20}[:=]\s*(['\"][A-Za-z0-9_\-]{24,}['\"])",
     "medium"),
    # Keep passwords but require quotes; avoid matching long unquoted text
    ("password_inline", "Hardcoded password",
     r"(?i)\bpassword\b\s*[:=]\s*(['\"][^'\"\s]{8,}['\"])", "high"),
]

# If a path matches any of these, we only do a "light" scan (no broad patterns)
_ALLOWLIST_PATHS: Tuple[re.Pattern, ...] = (
    re.compile(r"\.md$", re.IGNORECASE),
    re.compile(r"\.txt$", re.IGNORECASE),
    re.compile(r"LICENSE$", re.IGNORECASE),
    re.compile(r"CHANGELOG", re.IGNORECASE),
)

# Additional, context-aware detectors (entropy, etc.)
ALL_SECRET_DETECTORS = [
    EntropySecretsDetector(),
]


class SecretsDetector:
    name = "secrets"

    def scan(self, path: str, content: str) -> List[Finding]:
        # Allow-list: only run a strict subset of rules to reduce noise in prose files
        light = any(p.search(path) for p in _ALLOWLIST_PATHS)
        findings: List[Finding] = []

        seen: Set[Tuple[str, int, int]] = set()  # (rule_id, start, end)

        def _add(rule_id: str, sev: str, reason: str, m: re.Match) -> None:
            key = (rule_id, m.start(), m.end())
            if key in seen:
                return
            seen.add(key)
            findings.append(
                Finding(
                    path=path,
                    scanner=self.name,
                    rule_id=rule_id,
                    severity=sev,
                    reason=reason,
                    evidence=self._mask(content, m),
                )
            )

        # 1) Pattern rules
        for rule_id, desc, rx, sev in _SECRET_PATTERNS:
            if light and rule_id not in {"gh_token", "aws_secret_key"}:
                continue
            for m in rx.finditer(content):
                _add(rule_id, sev, desc, m)

        # 2) Context-aware detectors (e.g., entropy)
        # These return fully formed Finding objects already, so just extend.
        for det in ALL_SECRET_DETECTORS:
            sub_findings = det.scan(path, content)
            # de-dup against pattern rules by span+rule_id if possible
            for f in sub_findings:
                # try to recover a span if detector stored it; if not, rely on rule_id+path text de-dupe
                # entropy detector doesn't provide spans, so just append if not identical object already
                if not any(
                    (f.rule_id == ef.rule_id and f.path == ef.path and f.reason == ef.reason and f.evidence == ef.evidence)
                    for ef in findings
                ):
                    findings.append(f)

        return findings

    def _mask(self, text: str, match: re.Match) -> str:
        start, end = match.span()
        pre = text[max(0, start - 6): start]
        post = text[end: min(len(text), end + 6)]
        return f"{pre}{MASK}{post}"

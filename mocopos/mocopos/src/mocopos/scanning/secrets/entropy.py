# src/mocopos/scanning/secrets/entropy.py
from __future__ import annotations
import math
import os
import re
from typing import List

from mocopos.core.result_types import Finding

# Heuristic: long-ish base64/base62 candidates (no spaces)
CANDIDATE_RX = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=_-]{24,}(?![A-Za-z0-9+/=])")

# Common “not a secret” shapes
HEX_RX = re.compile(r"^[0-9a-f]{32,64}$", re.IGNORECASE)
UUID_RX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Obvious safe prefixes that look “token-ish” but are not credentials
SAFE_PREFIXES = ("http", "https", "ssh-", "rsa-", "ecdsa-", "-----begin", "data:")

# Code-ish extensions only (skip .md to reduce noise)
SCAN_EXTS = (
    ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".env", ".ini", ".cfg", ".toml",
    ".sh", ".bash", ".zsh", ".ps1",
)

# Extra belt & suspenders: even if SCAN_EXTS match, skip these basenames/paths
NOISY_BASENAMES = {
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "repo_db_mapping.json",
}
NOISY_PATH_SNIPPETS = (
    "/docs/", "/website/", "/fixtures/", "/fixture/", "/testdata/", "/tests/data/",
    "/samples/", "/sample_data/", "/webchat/", "/dashboard/", "/frontend_", "/client/",
)

# Require some nearby “secret-ish” context within this many chars
CONTEXT_RADIUS = 80
CONTEXT_WORDS = re.compile(
    r"(secret|secrets?|token|api[_-]?key|access[_-]?key|bearer|auth|password|pwd|credential)",
    re.IGNORECASE,
)

# Also allow config-like assignments: KEY=VALUE or "key": "VALUE" or key: VALUE
ASSIGNMENT_NEARBY = re.compile(
    r'[:=]\s*["\']?[A-Za-z0-9+/=_-]{10,}["\']?'
)

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

def _mixed_classes(s: str) -> int:
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_sym   = any(c in "+/=_-" for c in s)
    return int(has_upper) + int(has_lower) + int(has_digit) + int(has_sym)

def _looks_noisy_path(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    if os.path.basename(p) in NOISY_BASENAMES:
        return True
    return any(sn in p for sn in NOISY_PATH_SNIPPETS)

class EntropySecretsDetector:
    """
    Context-aware entropy rule:
      - only code-ish files
      - skips well-known noisy lockfiles/paths
      - requires mixed classes + entropy + length
      - requires nearby context words OR config-like assignment
    """
    name = "entropy_secrets"

    def scan(self, path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []

        # Quick gates
        if not path.endswith(SCAN_EXTS):
            return findings
        if _looks_noisy_path(path):
            return findings

        for m in CANDIDATE_RX.finditer(content):
            token = m.group(0)
            t_low = token.lower()

            # Guardrails
            if t_low.startswith(SAFE_PREFIXES):
                continue
            if len(token) > 2000:
                continue
            if UUID_RX.match(token) or HEX_RX.match(token):
                continue
            if _mixed_classes(token) < 3:
                continue

            # Entropy & length
            ent = shannon_entropy(token)
            if ent < 4.3 or len(token) < 40:
                continue

            # Require local context
            start = max(0, m.start() - CONTEXT_RADIUS)
            end   = min(len(content), m.end() + CONTEXT_RADIUS)
            window = content[start:end]

            if not (CONTEXT_WORDS.search(window) or ASSIGNMENT_NEARBY.search(window)):
                # No “secret-ish” context nearby → skip
                continue

            findings.append(
                Finding(
                    path=path,
                    scanner=self.name,
                    rule_id="high_entropy_candidate",
                    severity="medium",
                    reason=f"High-entropy token-like string near secret-ish context (entropy={ent:.2f}, len={len(token)}).",
                    evidence="****redacted****",
                )
            )

        return findings

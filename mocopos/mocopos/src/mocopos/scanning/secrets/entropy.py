from __future__ import annotations
import math
import re
from typing import List
from mocopos.core.result_types import Finding

# Base64/base62-ish token candidates (no spaces)
CANDIDATE_RX = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=_-]{24,}(?![A-Za-z0-9+/=])")

HEX_RX = re.compile(r"^[0-9a-f]{32,64}$", re.IGNORECASE)    # sha1/sha256-like
UUID_RX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)

SAFE_PREFIXES = ("http", "https", "ssh-", "rsa-", "ecdsa-", "-----begin", "data:")

SCAN_EXTS = (
    # skip markdown by default to reduce noise: no ".md" here
    ".py",".js",".ts",".json",".yaml",".yml",".env",".ini",".cfg",".toml",".sh",".bash",".zsh",".ps1"
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
    return sum([has_upper, has_lower, has_digit, has_sym])

class EntropySecretsDetector:
    name = "entropy_secrets"

    def scan(self, path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        if not path.endswith(SCAN_EXTS):
            return findings

        for m in CANDIDATE_RX.finditer(content):
            token = m.group(0)
            t_low = token.lower()
            if t_low.startswith(SAFE_PREFIXES):
                continue
            if len(token) > 2000:
                continue
            if UUID_RX.match(token) or HEX_RX.match(token):
                continue
            if _mixed_classes(token) < 3:  # require at least 3 of [upper,lower,digit,symbol]
                continue

            ent = shannon_entropy(token)
            # Slightly higher threshold and min length to reduce noise
            if ent >= 4.3 and len(token) >= 40:
                findings.append(Finding(
                    path=path,
                    scanner=self.name,
                    rule_id="high_entropy_candidate",
                    severity="medium",
                    reason=f"High-entropy token-like string (entropy={ent:.2f}, len={len(token)}).",
                    evidence="****redacted****"
                ))
        return findings

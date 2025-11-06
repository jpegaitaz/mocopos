from __future__ import annotations
import math
import re
from typing import List
from mocopos.core.result_types import Finding

# === Heuristics ===

# Only scan source-like files. INTENTIONALLY exclude .json/.yaml/.yml to avoid lockfiles & huge data blobs.
SCAN_EXTS = (
    ".py", ".js", ".ts", ".env", ".ini", ".cfg", ".toml", ".sh", ".bash", ".zsh", ".ps1"
)

# Hard skip known lockfiles & dependency metadata anywhere in the path
LOCKFILE_RX = re.compile(
    r"(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Pipfile\.lock|poetry\.lock|poetry\.toml|"
    r"Cargo\.lock|composer\.lock|Podfile\.lock|package-lock\.json5?)$",
    re.IGNORECASE,
)

# Base64/base62-ish token candidates (no spaces)
CANDIDATE_RX = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=_-]{24,}(?![A-Za-z0-9+/=])")

# Obvious non-secrets
HEX_RX = re.compile(r"^[0-9a-f]{32,64}$", re.IGNORECASE)  # sha1/sha256-like
UUID_RX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
SAFE_PREFIXES = ("http", "https", "ssh-", "rsa-", "ecdsa-", "-----begin", "data:")

# Require nearby “secret-y” context to reduce false positives
CONTEXT_HINTS_RX = re.compile(
    r"(?i)(secret|token|api[_-]?key|bearer|auth(entication|orization)?|private|password|sign(ature)?|access[_-]?key)"
)

MASK = "****redacted****"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _mixed_classes(s: str) -> int:
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_sym = any(c in "+/=_-" for c in s)
    return sum((has_upper, has_lower, has_digit, has_sym))


class EntropySecretsDetector:
    name = "entropy_secrets"

    def scan(self, path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        if not path.endswith(SCAN_EXTS):
            return findings
        if LOCKFILE_RX.search(path):
            return findings

        for m in CANDIDATE_RX.finditer(content):
            token = m.group(0)
            low = token.lower()

            # quick rejects
            if low.startswith(SAFE_PREFIXES):      continue
            if len(token) > 2000:                  continue
            if UUID_RX.match(token) or HEX_RX.match(token):  continue
            if _mixed_classes(token) < 3:          continue

            ent = shannon_entropy(token)
            if ent < 4.3 or len(token) < 40:       continue

            # local window (line-scoped + small margins)
            start, end = m.span()
            line_start = content.rfind("\n", 0, start) + 1
            line_end   = content.find("\n", end)
            if line_end == -1: line_end = len(content)
            window_start = max(0, line_start, start - 60)
            window_end   = min(len(content), line_end, end + 60)
            window = content[window_start:window_end]

            # Must have a secret-y key/name AND assignment-like context nearby
            if not KEY_HINT_RX.search(window):     continue
            if BENIGN_KEY_RX.search(window):       continue
            if not ASSIGN_NEAR_RX.search(window):  continue

            findings.append(Finding(
                path=path,
                scanner=self.name,
                rule_id="high_entropy_candidate",
                severity="medium",
                reason=f"High-entropy token-like string with assignment + secret context (entropy={ent:.2f}, len={len(token)}).",
                evidence=MASK,
            ))

        return findings

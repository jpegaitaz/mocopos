from __future__ import annotations

# Heuristic: treat as binary if there are a lot of NULs or non-texty bytes.
def is_probably_binary(s: str) -> bool:
    if not s:
        return False
    # If string contains lots of NULs, it's likely binary after a lossy decode
    nul_count = s.count("\x00")
    if nul_count > 0:
        return True
    # If >30% of chars are non-printable (excluding common whitespace), call it binary
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in s)
    return printable / max(1, len(s)) < 0.7

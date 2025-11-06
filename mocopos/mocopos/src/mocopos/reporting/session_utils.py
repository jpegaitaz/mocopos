import os
import time
import hashlib
from datetime import datetime, timezone
from typing import Optional, Iterable

def utc_stamp() -> str:
    # e.g., 20251011_135940Z
    return datetime.utcnow().strftime("%Y%m%d_%H%M%SZ")

def short_hash(s: str, length: int = 6) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:length].upper()

def generate_session_id(seed: Optional[str] = None) -> str:
    """
    Generates a compact, mostly unique, sortable-ish session id.
    If seed is provided, derive a stable short hash from it.
    Otherwise, use current time + process info for entropy.
    """
    if seed:
        return short_hash(seed, 6)
    rnd = f"{time.time_ns()}-{os.getpid()}-{os.urandom(4).hex()}"
    return short_hash(rnd, 6)

def infer_session_id(candidates: Iterable[str]) -> Optional[str]:
    """
    Given a list of candidate strings (e.g., run.id, run.session_id),
    pick the first non-empty and collapse to a short hash.
    """
    for c in candidates:
        if c and isinstance(c, str) and c.strip():
            return short_hash(c.strip(), 6)
    return None

def stamp_prefix(session_id: str, ts: Optional[str] = None) -> str:
    ts = ts or utc_stamp()
    return f"{ts}-{session_id}"

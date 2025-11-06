from __future__ import annotations
from dataclasses import dataclass

@dataclass
class Session:
    session_id: str
    started_at: str
    finished_at: str | None = None

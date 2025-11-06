from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Finding:
    path: str
    scanner: str
    rule_id: str
    severity: str
    reason: str
    evidence: Optional[str] = None
    code_span: Optional[str] = None

@dataclass
class RepoInfo:
    owner: str
    name: str
    ref: str
    commit: str

@dataclass
class Stats:
    files_scanned: int
    bytes_scanned: int
    scanners_used: List[str]

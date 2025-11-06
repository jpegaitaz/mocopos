from __future__ import annotations
from typing import Tuple, List
from mocopos.core.result_types import Finding

DOC_LIKE_DIRS = (".github/", ".vscode/", "docs/", "doc/", "documentation/", "examples/")
DOC_LIKE_EXTS = (".md", ".rst", ".adoc", ".txt")

def _is_doc_like(path: str) -> bool:
    p = path.lower()
    return p.endswith(DOC_LIKE_EXTS) or any(seg in p for seg in DOC_LIKE_DIRS)

def classify(findings: List[Finding]) -> Tuple[str, str]:
    if not findings:
        return "Safe", "No findings detected."

    severities = {f.severity for f in findings}
    # If everything comes only from the entropy detector AND looks like docs/config, relax it.
    if all(f.scanner == "entropy_secrets" for f in findings) and all(_is_doc_like(f.path) for f in findings):
        return "Safe", "Only high-entropy strings found in docs/config; likely non-secrets."

    if "critical" in severities or "high" in severities:
        return "Threat", "High-risk secrets or dangerous patterns detected."
    if "medium" in severities:
        return "Potential Threat", "Potentially sensitive tokens or patterns found."
    return "Potential Threat", "Low-risk indicators found."

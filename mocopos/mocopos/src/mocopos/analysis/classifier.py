from __future__ import annotations
from typing import Tuple, List
from mocopos.core.result_types import Finding

def classify(findings: List[Finding]) -> Tuple[str, str]:
    if not findings:
        return "Safe", "No findings detected."
    severities = {f.severity for f in findings}
    if "critical" in severities or "high" in severities:
        return "Threat", "High-risk secrets or credentials detected."
    if "medium" in severities:
        return "Potential Threat", "Potentially sensitive tokens found."
    return "Potential Threat", "Low-risk indicators found."

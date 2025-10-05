from __future__ import annotations
import json
import re
from typing import List
from mocopos.core.result_types import Finding

RISKY_PY_REQ = [
    (r"requests\s*<\s*2\.21", "Old requests (<2.21) had known vulns; upgrade recommended.", "medium"),
    (r"pyyaml\s*<\s*5\.4", "PyYAML before 5.4 has known issues; upgrade recommended.", "medium"),
    (r"flask\s*<\s*1\.0", "Very old Flask; upgrade recommended.", "low"),
]

class DepsAudit:
    name = "deps_audit"

    def scan(self, path: str, content: str) -> List[Finding]:
        if path.endswith(("requirements.txt", "requirements-dev.txt")):
            return self._scan_requirements(path, content)
        if path.endswith(("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock")):
            return self._scan_js(path, content)
        return []

    def _scan_requirements(self, path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        for rx, msg, sev in RISKY_PY_REQ:
            if re.search(rx, content, flags=re.IGNORECASE):
                findings.append(Finding(
                    path=path,
                    scanner=self.name,
                    rule_id="py_dep_risk",
                    severity=sev,
                    reason=msg
                ))
        return findings

    def _scan_js(self, path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        # very light heuristics; we’re not pulling advisories, just hints
        if path.endswith("package.json"):
            try:
                data = json.loads(content)
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                # example heuristic
                if any(name.lower() == "jquery" for name in deps):
                    findings.append(Finding(
                        path=path,
                        scanner=self.name,
                        rule_id="js_dep_risk",
                        severity="low",
                        reason="jQuery present; ensure version is up to date and minimize DOM injection."
                    ))
            except Exception:
                pass
        return findings

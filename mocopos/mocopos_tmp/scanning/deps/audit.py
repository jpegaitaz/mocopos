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

# Simple levenshtein distance to catch blatant typos (keep it tiny to avoid noise)
def _lev(a: str, b: str) -> int:
    if a == b: return 0
    if not a: return len(b)
    if not b: return len(a)
    dp = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        prev = dp[0]
        dp[0] = i
        for j, cb in enumerate(b, 1):
            cur = dp[j]
            dp[j] = min(
                dp[j] + 1,       # deletion
                dp[j-1] + 1,     # insertion
                prev + (ca != cb) # substitution
            )
            prev = cur
    return dp[-1]

POPULAR = {"react","express","lodash","axios","commander","typescript","jest","vite","next","vue","rxjs","request","requests","flask"}
SUSPICIOUS_CMDS_RX = re.compile(r"(curl|wget|nc|powershell|Invoke-WebRequest|bash\s+-c|sh\s+-c)", re.IGNORECASE)

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
                    path=path, scanner=self.name, rule_id="py_dep_risk", severity=sev, reason=msg
                ))
        # Heuristic: flag unpinned lines (no == and not URL/VCS)
        for line in content.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "@" in s or "git+" in s or "http" in s:
                continue
            if "==" not in s:
                findings.append(Finding(
                    path=path, scanner=self.name, rule_id="py_unpinned", severity="low",
                    reason=f"Unpinned requirement '{s}'. Use exact versions for reproducibility."
                ))
        return findings

    def _scan_js(self, path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        if path.endswith("package.json"):
            try:
                data = json.loads(content)
            except Exception:
                return findings
            deps = {}
            for k in ("dependencies", "devDependencies", "optionalDependencies"):
                deps.update(data.get(k, {}))

            # typosquatting heuristic: very small edit distance to popular libs but not equal
            for name in deps:
                for popular in POPULAR:
                    if name == popular:
                        continue
                    if _lev(name.lower(), popular.lower()) == 1:
                        findings.append(Finding(
                            path=path, scanner=self.name, rule_id="npm_typosquat", severity="medium",
                            reason=f"Dependency '{name}' is one edit away from '{popular}'. Verify package legitimacy."
                        ))
                        break

            # risky lifecycle scripts
            scripts = data.get("scripts", {})
            for hook in ("preinstall", "install", "postinstall"):
                cmd = scripts.get(hook)
                if isinstance(cmd, str) and SUSPICIOUS_CMDS_RX.search(cmd):
                    findings.append(Finding(
                        path=path, scanner=self.name, rule_id="npm_risky_lifecycle", severity="high",
                        reason=f"'{hook}' script runs network/shell command; risk of supply-chain abuse."
                    ))
        return findings

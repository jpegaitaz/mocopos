from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any
import re
import yaml

from mocopos.core.result_types import Finding

FLOATING_REFS = {"master", "main", "latest", "edge"}

RISKY_RUN_RX = re.compile(r"(curl|wget|nc|powershell|Invoke-WebRequest|bash\s+-c|sh\s+-c)", re.IGNORECASE)
SECRET_TOKEN_RX = re.compile(r"(GITHUB_TOKEN|secrets\.[A-Z0-9_]+)", re.IGNORECASE)

# Policy
try:
    _POL = {}
    pol_path = Path(__file__).resolve().parents[4] / "configs" / "policies.yaml"
    if pol_path.exists():
        _POL = yaml.safe_load(pol_path.read_text()) or {}
except Exception:
    _POL = {}

_REQUIRE_PINNED = bool(_POL.get("ci", {}).get("require_pinned", True))
_REQUIRE_SHA = bool(_POL.get("ci", {}).get("require_sha_pin", False))

class GitHubActionsScanner:
    name = "github_actions"

    def scan(self, path: str, content: str) -> List[Finding]:
        if not (path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))):
            return []

        try:
            data = list(yaml.safe_load_all(content))
        except Exception:
            return []

        findings: List[Finding] = []

        for doc in data:
            if not isinstance(doc, dict):
                continue
            jobs = (doc.get("jobs") or {})
            for job in jobs.values():
                steps = (job or {}).get("steps") or []
                for step in steps:
                    # 'uses' pinning
                    uses = step.get("uses")
                    if isinstance(uses, str):
                        if "@" in uses:
                            _, ref = uses.rsplit("@", 1)
                            if _REQUIRE_SHA and not re.fullmatch(r"[0-9a-fA-F]{40}", ref or ""):
                                findings.append(Finding(
                                    path=path, scanner=self.name, rule_id="gha_uses_not_sha",
                                    severity="medium",
                                    reason=f"Action '{uses}' not pinned to a full-length commit SHA."
                                ))
                            elif _REQUIRE_PINNED and (ref in FLOATING_REFS):
                                findings.append(Finding(
                                    path=path, scanner=self.name, rule_id="gha_uses_floating",
                                    severity="medium",
                                    reason=f"Action '{uses}' pinned to floating ref '{ref}'."
                                ))
                        else:
                            if _REQUIRE_PINNED:
                                findings.append(Finding(
                                    path=path, scanner=self.name, rule_id="gha_uses_unpinned",
                                    severity="medium",
                                    reason=f"Action '{uses}' not pinned (missing @ref)."
                                ))
                    # 'run' secrets exfil
                    run = step.get("run")
                    if isinstance(run, str):
                        if RISKY_RUN_RX.search(run) and SECRET_TOKEN_RX.search(run):
                            findings.append(Finding(
                                path=path, scanner=self.name, rule_id="gha_secrets_exfil",
                                severity="high",
                                reason="Step runs network command and references secrets/GITHUB_TOKEN."
                            ))
        return findings

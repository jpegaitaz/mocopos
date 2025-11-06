from __future__ import annotations
import ast
from typing import List
from mocopos.core.result_types import Finding

class StaticRiskDetector:
    name = "static_risk"

    def scan(self, path: str, content: str) -> List[Finding]:
        # Only check likely text/code files
        if not path.endswith((".py", ".js", ".ts", ".sh", ".bash")):
            return []
        if path.endswith((".js", ".ts", ".sh", ".bash")):
            # simple regex-free heuristics (string contains) for now
            return self._text_heuristics(path, content)

        # Python AST-based checks
        findings: List[Finding] = []
        try:
            tree = ast.parse(content)
        except Exception:
            return findings

        for node in ast.walk(tree):
            # eval/exec
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"eval", "exec"}:
                    findings.append(Finding(
                        path=path,
                        scanner=self.name,
                        rule_id=f"py_{node.func.id}",
                        severity="medium",
                        reason=f"Use of {node.func.id} can enable code injection."
                    ))
            # subprocess(..., shell=True)
            if isinstance(node, ast.Call) and hasattr(node.func, "attr"):
                try:
                    func_name = node.func.attr
                except Exception:
                    func_name = ""
                if func_name in {"Popen", "call", "run"}:
                    # rough check for shell=True kwarg
                    for kw in node.keywords or []:
                        if kw.arg == "shell" and getattr(kw.value, "value", None) is True:
                            findings.append(Finding(
                                path=path,
                                scanner=self.name,
                                rule_id="py_subprocess_shell_true",
                                severity="high",
                                reason="subprocess with shell=True increases risk of command injection."
                            ))
        return findings

    def _text_heuristics(self, path: str, content: str) -> List[Finding]:
        f: List[Finding] = []
        # naive checks for shell scripts and js/ts files
        lowered = content.lower()
        if "eval(" in content:
            f.append(Finding(
                path=path,
                scanner=self.name,
                rule_id="text_eval_call",
                severity="medium",
                reason="Use of eval() can enable code injection."
            ))
        if "child_process.exec(" in lowered or "child_process.execsync(" in lowered:
            f.append(Finding(
                path=path,
                scanner=self.name,
                rule_id="node_exec_call",
                severity="medium",
                reason="Node.js exec/execSync used; review input validation."
            ))
        return f

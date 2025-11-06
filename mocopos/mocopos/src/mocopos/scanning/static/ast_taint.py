from __future__ import annotations
import ast
import ipaddress
import re
from typing import List, Set, Dict, Any, Optional

from mocopos.core.result_types import Finding

# Tiny config shim; if not present, we use safe defaults.
try:
    import yaml  # type: ignore
    from pathlib import Path
    _POL = {}
    _pol_path = Path(__file__).resolve().parents[4] / "configs" / "policies.yaml"
    if _pol_path.exists():
        _POL = yaml.safe_load(_pol_path.read_text()) or {}
except Exception:
    _POL = {}

_ALLOWED_DOMAINS = set(_POL.get("network", {}).get("allowed_domains", []))
_BLOCK_PRIVATE = bool(_POL.get("network", {}).get("block_private", True))
_SAFE_ROOT = str(_POL.get("filesystem", {}).get("safe_root", "/workspace"))

SHELL_SINKS = {("subprocess", "run"), ("subprocess", "call"), ("subprocess", "Popen")}
DANGEROUS_BUILTINS = {"eval", "exec"}
FILE_SINKS = {("os", "remove"), ("os", "unlink"), ("shutil", "rmtree"), ("builtins", "open")}
HTTP_CLIENTS = {("requests", "get"), ("requests", "post"), ("requests", "put"), ("requests", "delete")}

URL_RE = re.compile(r"https?://([^/\s:]+)")

def _domain_from(url: str) -> Optional[str]:
    m = URL_RE.search(url)
    return m.group(1) if m else None

def _is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        # host is a domain; non-IP – not private by IP rules
        return False

class TaintRiskDetector:
    """
    Very light taint analysis:
      - mark function args as tainted
      - propagate simple Name <- Name assignments
      - flag sinks: eval/exec, subprocess(..., shell=True), file ops with tainted paths,
                    HTTP with tainted URL and no allowlist / private IPs (if configured)
    """
    name = "taint_risk"

    def scan(self, path: str, content: str) -> List[Finding]:
        if not path.endswith((".py",)):
            return []

        try:
            tree = ast.parse(content)
        except Exception:
            return []

        findings: List[Finding] = []
        tainted: Set[str] = set()

        class Visitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef):
                # parameters are taint sources
                for a in node.args.args:
                    tainted.add(a.arg)
                self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                for a in node.args.args:
                    tainted.add(a.arg)
                self.generic_visit(node)

            def visit_Assign(self, node: ast.Assign):
                # x = y  (Name <- Name) simple propagation
                try:
                    if isinstance(node.value, ast.Name):
                        src = node.value.id
                        if src in tainted:
                            for t in node.targets:
                                if isinstance(t, ast.Name):
                                    tainted.add(t.id)
                except Exception:
                    pass
                self.generic_visit(node)

            def visit_Call(self, node: ast.Call):
                # builtin eval/exec
                if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_BUILTINS:
                    findings.append(Finding(
                        path=path, scanner=TaintRiskDetector.name,
                        rule_id=f"py_{node.func.id}",
                        severity="high",
                        reason=f"Use of {node.func.id} with potential user-controlled input."
                    ))

                # Attribute calls: module.func(...)
                mod = getattr(node.func, "value", None)
                attr = getattr(node.func, "attr", None)
                mod_id = getattr(mod, "id", None) if isinstance(mod, ast.Name) else None

                # subprocess.* sinks
                if mod_id and attr and (mod_id, attr) in SHELL_SINKS:
                    shell_true = any((k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True)
                                     for k in (node.keywords or []))
                    arg_tainted = any(isinstance(a, ast.Name) and a.id in tainted for a in node.args)
                    if shell_true and arg_tainted:
                        findings.append(Finding(
                            path=path, scanner=TaintRiskDetector.name,
                            rule_id="py_subprocess_shell_tainted",
                            severity="critical",
                            reason="subprocess with shell=True using tainted input (command injection risk)."
                        ))
                    elif arg_tainted:
                        findings.append(Finding(
                            path=path, scanner=TaintRiskDetector.name,
                            rule_id="py_subprocess_tainted",
                            severity="high",
                            reason="subprocess invoked with tainted input. Validate/allowlist args."
                        ))

                # file sinks (open/remove/rmtree with tainted path)
                if (mod_id, attr) in FILE_SINKS or (isinstance(node.func, ast.Name) and node.func.id == "open"):
                    # first positional arg is path
                    if node.args:
                        a0 = node.args[0]
                        if isinstance(a0, ast.Name) and a0.id in tainted:
                            findings.append(Finding(
                                path=path, scanner=TaintRiskDetector.name,
                                rule_id="py_file_op_tainted",
                                severity="high",
                                reason=f"File operation uses tainted path; enforce safe-root {_SAFE_ROOT} and normalize."
                            ))

                # HTTP requests with tainted URLs or off-allowlist
                if mod_id and attr and (mod_id, attr) in HTTP_CLIENTS and node.args:
                    url_arg = node.args[0]
                    url_val: Optional[str] = None
                    taint = False
                    if isinstance(url_arg, ast.Constant) and isinstance(url_arg.value, str):
                        url_val = url_arg.value
                    elif isinstance(url_arg, ast.Name) and url_arg.id in tainted:
                        taint = True
                    if taint:
                        findings.append(Finding(
                            path=path, scanner=TaintRiskDetector.name,
                            rule_id="py_http_url_tainted",
                            severity="high",
                            reason="HTTP request with tainted URL; enforce allowlist."
                        ))
                    if url_val:
                        host = _domain_from(url_val)
                        if host:
                            if _BLOCK_PRIVATE:
                                try:
                                    if _is_private_host(host):
                                        findings.append(Finding(
                                            path=path, scanner=TaintRiskDetector.name,
                                            rule_id="py_http_private_target",
                                            severity="high",
                                            reason=f"HTTP call to private/loopback address ({host}) blocked by policy."
                                        ))
                                except Exception:
                                    pass
                            if _ALLOWED_DOMAINS and not any(dom in host for dom in _ALLOWED_DOMAINS):
                                findings.append(Finding(
                                    path=path, scanner=TaintRiskDetector.name,
                                    rule_id="py_http_off_allowlist",
                                    severity="medium",
                                    reason=f"Domain {host} not in allowed_domains policy."
                                ))
                self.generic_visit(node)

        Visitor().visit(tree)
        return findings

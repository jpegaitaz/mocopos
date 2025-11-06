# src/mocopos/llm/interpreter.py
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

from openai import OpenAI

from mocopos.config.loader import Settings
from mocopos.core.session import Session
from mocopos.core.workflow import Workflow
from mocopos.connectors.github_client import GithubClient


DEFAULT_MODEL = os.getenv("MOCOPOS_OPENAI_MODEL", "gpt-4o-mini")

_REPO_URL_RX = re.compile(
    r"https?://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<name>[A-Za-z0-9_.-]+)(?:\.git)?(?:[^\s]*)?"
)


class LLMInterpreter:
    """
    Natural-language front-end that lets the model choose a Mocopos action
    by calling registered tools (scan repo, show rate limit).

    - Uses OpenAI Responses API with tool calls.
    - Adds a heuristic fallback: if the model does not issue a tool call but the user
      gave a GitHub repo URL, we run the scan directly.
    """

    def __init__(self, settings: Optional[Settings] = None, model: str = DEFAULT_MODEL):
        self.settings = settings or Settings.load()
        self.model = model
        # Requires OPENAI_API_KEY in env
        self.client = OpenAI()

    # ---------------------------
    # Tool specs (what the model sees)
    # ---------------------------
    def _tool_specs(self) -> List[Dict[str, Any]]:
        # Keep tools[i].name at top-level and also nested "function"
        return [
            {
                "name": "scan_repo",
                "type": "function",
                "description": "Scan a single GitHub repository and return a concise security summary.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo_url": {"type": "string", "description": "Full GitHub URL (e.g. https://github.com/org/name)."},
                        "ref": {"type": "string", "nullable": True, "description": "Optional branch/tag/SHA to scan."},
                        "include_globs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "nullable": True,
                            "description": "Only scan files matching any of these globs.",
                        },
                        "exclude_globs": {
                            "type": "array",
                            "items": {"type": "string"},
                            "nullable": True,
                            "description": "Skip files matching any of these globs.",
                        },
                    },
                    "required": ["repo_url"],
                    "additionalProperties": False,
                },
                "function": {
                    "name": "scan_repo",
                    "description": "Scan a single GitHub repository and return a concise security summary.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "repo_url": {"type": "string"},
                            "ref": {"type": "string", "nullable": True},
                            "include_globs": {"type": "array", "items": {"type": "string"}, "nullable": True},
                            "exclude_globs": {"type": "array", "items": {"type": "string"}, "nullable": True},
                        },
                        "required": ["repo_url"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "name": "show_rate_limit",
                "type": "function",
                "description": "Show current GitHub REST rate-limit status for core and search.",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                "function": {
                    "name": "show_rate_limit",
                    "description": "Show current GitHub REST rate-limit status for core and search.",
                    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                },
            },
        ]

    # --------------------------------
    # Tool implementations (what runs)
    # --------------------------------
    def _impl_scan_repo(
        self,
        repo_url: str,
        ref: Optional[str] = None,
        include_globs: Optional[List[str]] = None,
        exclude_globs: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        session = Session(session_id=f"nl-scan:{repo_url}", started_at="")
        wf = Workflow(settings=self.settings, session=session)
        report = wf.run(
            repo_url=repo_url,
            ref=ref,
            include_globs=include_globs,
            exclude_globs=exclude_globs,
        )
        return {
            "repo": report.get("repo", {}),
            "stats": report.get("stats", {}),
            "classification": report.get("classification"),
            "summary": report.get("summary"),
            "findings_count": len(report.get("findings", []) or []),
        }

    def _impl_show_rate_limit(self) -> Dict[str, Any]:
        gh = GithubClient(api_base=self.settings.github.api_base)
        r = gh._request("GET", f"{gh.api_base}/rate_limit", tries=1)
        data = r.json()
        return {
            "core": (data.get("resources", {}) or {}).get("core", {}),
            "search": (data.get("resources", {}) or {}).get("search", {}),
        }

    # -----------------
    # Helpers
    # -----------------
    def _extract_repo_url(self, text: str) -> Optional[str]:
        m = _REPO_URL_RX.search(text or "")
        if not m:
            return None
        # Trim to exactly owner/name (drop extra subpaths like /tree/main)
        owner = m.group("owner")
        name = m.group("name")
        return f"https://github.com/{owner}/{name}"

    def _format_scan_summary(self, out: Dict[str, Any]) -> str:
        repo = out.get("repo", {}) or {}
        stats = out.get("stats", {}) or {}
        full = f"{repo.get('owner', '?')}/{repo.get('name', '?')}"
        ref = repo.get("ref") or "default-branch"
        files = stats.get("files_scanned", 0)
        bytes_scanned = stats.get("bytes_scanned", 0)
        findings = out.get("findings_count", 0)
        classification = out.get("classification", "Unscanned")
        summary = out.get("summary", "") or ""

        lines = [
            f"Scan complete for **{full}** @ **{ref}**",
            f"- Files scanned: {files}",
            f"- Bytes scanned: {bytes_scanned}",
            f"- Findings: {findings}",
            f"- Classification: **{classification}**",
            f"- Summary: {summary}",
        ]
        return "\n".join(lines)

    # -----------------
    # Chat entry point
    # -----------------
    def chat(self, user_text: str, history: Optional[List[Dict[str, str]]] = None) -> str:
        """
        Send a user message. If the model calls a tool, execute it and
        return the final assistant message (natural language).
        Includes a heuristic fallback if the model fails to call a tool.
        """
        msgs: List[Dict[str, Any]] = (history or []) + [
            {
                "role": "system",
                "content": (
                    "You are Mocopos' LLM interpreter.\n"
                    "- When the user provides a GitHub repository URL or asks to scan a repo, "
                    "you MUST call the `scan_repo` tool instead of replying with plain text.\n"
                    "- Prefer scanning with include/exclude hints if provided.\n"
                    "- Summarize results clearly with top risks, counts, and notable files.\n"
                    "- If scanning fails, explain the cause and suggest next steps."
                ),
            },
            {"role": "user", "content": user_text},
        ]

        # 1) Ask the model; it may emit tool calls
        first = self.client.responses.create(
            model=self.model,
            input=msgs,
            tools=self._tool_specs(),
            tool_choice="auto",
        )

        def _render_text(resp) -> str:
            txt = getattr(resp, "output_text", None)
            if txt:
                return txt
            parts: List[str] = []
            for item in getattr(resp, "output", []) or []:
                if getattr(item, "type", None) == "message":
                    for p in getattr(item, "content", []) or []:
                        if getattr(p, "type", None) == "output_text":
                            parts.append(getattr(p, "text", "") or "")
            return "\n".join([p for p in parts if p])

        # Collect tool calls
        tool_calls = []
        for item in getattr(first, "output", []) or []:
            if getattr(item, "type", None) == "tool_call":
                tool_calls.append(item)

        # 2) If no tools were called, try heuristic fallback for repo URLs
        if not tool_calls:
            repo_url = self._extract_repo_url(user_text)
            if repo_url:
                try:
                    out = self._impl_scan_repo(repo_url=repo_url)
                    return self._format_scan_summary(out)
                except Exception as e:
                    return f"Scan failed for {repo_url}: {e!r}"
            # Otherwise, just return the model’s text
            return _render_text(first) or "OK."

        # 3) Execute tool calls and supply their outputs
        tool_outputs: List[Dict[str, Any]] = []
        for call in tool_calls:
            name = getattr(call, "tool_name", None) or getattr(getattr(call, "tool_call", None), "name", None)
            raw_args = getattr(call, "arguments", None) or getattr(getattr(call, "tool_call", None), "arguments", None)

            if isinstance(raw_args, dict):
                args = raw_args
            else:
                try:
                    args = json.loads(raw_args or "{}")
                except Exception:
                    args = {}

            try:
                if name == "scan_repo":
                    out = self._impl_scan_repo(
                        repo_url=args.get("repo_url"),
                        ref=args.get("ref"),
                        include_globs=args.get("include_globs"),
                        exclude_globs=args.get("exclude_globs"),
                    )
                elif name == "show_rate_limit":
                    out = self._impl_show_rate_limit()
                else:
                    out = {"error": f"Unknown tool: {name}"}
            except Exception as e:
                out = {"error": f"tool '{name}' failed: {e!r}"}

            tool_outputs.append(
                {
                    "tool_call_id": getattr(call, "id", None),
                    "output": json.dumps(out, ensure_ascii=False),
                }
            )

        # 4) Provide tool outputs and return final text
        followup = self.client.responses.create(
            model=self.model,
            tool_outputs=tool_outputs,
        )
        final = _render_text(followup)
        if final:
            return final

        # As an extra safety, if we see exactly one scan_repo call, format it ourselves
        try:
            parsed = json.loads(tool_outputs[0]["output"])
            if isinstance(parsed, dict) and parsed.get("repo"):
                return self._format_scan_summary(parsed)
        except Exception:
            pass

        return json.dumps(tool_outputs, ensure_ascii=False)

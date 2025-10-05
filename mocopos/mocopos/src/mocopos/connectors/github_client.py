from __future__ import annotations

import base64
import os
import re
from typing import Dict, List, Tuple

import requests

class GithubClient:
    def __init__(self, api_base: str = "https://api.github.com"):
        self.api_base = api_base.rstrip("/")
        self.token = os.getenv("GITHUB_TOKEN")

    def _headers(self) -> Dict[str, str]:
        hdr = {"Accept": "application/vnd.github+json"}
        if self.token:
            hdr["Authorization"] = f"Bearer {self.token}"
        return hdr

    @staticmethod
    def parse_repo_url(url: str) -> Dict[str, str]:
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", url)
        if not m:
            raise ValueError("Invalid GitHub repository URL")
        return {"owner": m.group(1), "name": m.group(2)}

    def resolve_ref(self, owner: str, name: str, ref: str | None) -> Tuple[str, str]:
        if ref:
            r = requests.get(f"{self.api_base}/repos/{owner}/{name}/git/refs/heads/{ref}", headers=self._headers())
            if r.status_code == 200:
                return r.json()["object"]["sha"], ref
            r = requests.get(f"{self.api_base}/repos/{owner}/{name}/git/refs/tags/{ref}", headers=self._headers())
            r.raise_for_status()
            return r.json()["object"]["sha"], ref
        repo = requests.get(f"{self.api_base}/repos/{owner}/{name}", headers=self._headers())
        repo.raise_for_status()
        default_branch = repo.json()["default_branch"]
        branch = requests.get(f"{self.api_base}/repos/{owner}/{name}/branches/{default_branch}", headers=self._headers())
        branch.raise_for_status()
        return branch.json()["commit"]["sha"], default_branch

    def fetch_tree(self, owner: str, name: str, commit: str) -> List[Dict]:
        r = requests.get(f"{self.api_base}/repos/{owner}/{name}/git/trees/{commit}?recursive=1",
                         headers=self._headers())
        r.raise_for_status()
        tree = r.json().get("tree", [])
        files: List[Dict] = []
        for node in tree:
            if node.get("type") == "blob":
                files.append({"path": node["path"], "type": "blob", "size": node.get("size", 0)})
        return files

    def fetch_blob_content(self, owner: str, name: str, path: str) -> str:
        r = requests.get(f"{self.api_base}/repos/{owner}/{name}/contents/{path}", headers=self._headers())
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
        if isinstance(data, dict) and "content" in data:
            try:
                return data["content"]
            except Exception:
                return ""
        return ""

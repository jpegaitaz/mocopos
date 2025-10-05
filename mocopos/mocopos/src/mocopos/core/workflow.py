from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Any, List

from mocopos.config.loader import Settings
from mocopos.core.session import Session
from mocopos.core.result_types import Finding, RepoInfo, Stats
from mocopos.connectors.github_client import GithubClient
from mocopos.scanning.runner import ScannerRunner
from mocopos.analysis.classifier import classify

class Workflow:
    def __init__(self, settings: Settings, session: Session):
        self.settings = settings
        self.session = session

    def run(self, repo_url: str, ref: str | None) -> Dict[str, Any]:
        gh = GithubClient(api_base=self.settings.github.api_base)
        repo = gh.parse_repo_url(repo_url)
        commit_sha, used_ref = gh.resolve_ref(repo["owner"], repo["name"], ref)

        files = gh.fetch_tree(owner=repo["owner"], name=repo["name"], commit=commit_sha)
        runner = ScannerRunner(max_bytes=self.settings.scanner.max_bytes_per_file, github=gh,
                               owner=repo["owner"], name=repo["name"])
        findings: List[Finding] = []
        bytes_scanned = 0
        for f in files:
            if f["type"] != "blob":
                continue
            if f.get("size", 0) > self.settings.scanner.max_bytes_per_file:
                continue
            content = gh.fetch_blob_content(owner=repo["owner"], name=repo["name"], path=f["path"])
            bytes_scanned += len(content.encode("utf-8", errors="ignore"))
            findings.extend(runner.scan_file(path=f["path"], content=content))

        stats = Stats(
            files_scanned=sum(1 for x in files if x.get("type") == "blob"),
            bytes_scanned=bytes_scanned,
            scanners_used=runner.scanners_used()
        )
        classification, summary = classify(findings)

        self.session.finished_at = datetime.now(timezone.utc).isoformat()

        report: Dict[str, Any] = {
            "session_id": self.session.session_id,
            "started_at": self.session.started_at,
            "finished_at": self.session.finished_at,
            "repo": RepoInfo(owner=repo["owner"], name=repo["name"], ref=used_ref, commit=commit_sha).__dict__,
            "stats": stats.__dict__,
            "findings": [f.__dict__ for f in findings],
            "classification": classification,
            "summary": summary,
            "policy_flags": []
        }
        return report

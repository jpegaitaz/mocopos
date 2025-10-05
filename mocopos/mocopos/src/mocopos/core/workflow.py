from __future__ import annotations

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List

from mocopos.config.loader import Settings
from mocopos.core.session import Session
from mocopos.core.result_types import Finding, RepoInfo, Stats
from mocopos.connectors.github_client import GithubClient
from mocopos.scanning.runner import ScannerRunner
from mocopos.analysis.classifier import classify

def _drop_none(d: Dict[str, Any]) -> Dict[str, Any]:
    """Drop keys whose values are None (shallow)."""
    return {k: v for k, v in d.items() if v is not None}

def _sanitize(obj: Any) -> Any:
    """
    Recursively:
      - remove keys with None values
      - remove None items from lists
    """
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_sanitize(v) for v in obj if v is not None]
    return obj

class Workflow:
    def __init__(self, settings: Settings, session: Session):
        self.settings = settings
        self.session = session

    def run(
        self,
        repo_url: str,
        ref: str | None,
        include_globs: List[str] | None = None,
        exclude_globs: List[str] | None = None
    ) -> Dict[str, Any]:
        gh = GithubClient(api_base=self.settings.github.api_base)
        repo = gh.parse_repo_url(repo_url)
        commit_sha, used_ref = gh.resolve_ref(repo["owner"], repo["name"], ref)

        files = gh.fetch_tree(owner=repo["owner"], name=repo["name"], commit=commit_sha)

        runner = ScannerRunner(
            max_bytes=self.settings.scanner.max_bytes_per_file,
            github=gh,
            owner=repo["owner"],
            name=repo["name"],
            ignore_globs=(exclude_globs if exclude_globs is not None else self.settings.scanner.ignore_globs),
            include_globs=(include_globs or []),
        )

        findings: List[Finding] = []
        bytes_scanned = 0

        # Only blobs under size limit
        targets = [
            f for f in files
            if f.get("type") == "blob" and f.get("size", 0) <= self.settings.scanner.max_bytes_per_file
        ]

        def fetch_and_scan(pth: str) -> tuple[int, List[Finding]]:
            content = gh.fetch_blob_content(owner=repo["owner"], name=repo["name"], path=pth)
            b = len(content.encode("utf-8", errors="ignore"))
            return b, runner.scan_file(path=pth, content=content)

        # Keep thread count sane to respect rate limits
        max_workers = min(12, max(2, len(targets) // 10 or 2))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(fetch_and_scan, f["path"]): f["path"] for f in targets}
            for fut in as_completed(futs):
                b, fnds = fut.result()
                bytes_scanned += b
                findings.extend(fnds)

        stats = Stats(
            files_scanned=sum(1 for x in files if x.get("type") == "blob"),
            bytes_scanned=bytes_scanned,
            scanners_used=runner.scanners_used(),
        )
        classification, summary = classify(findings)

        self.session.finished_at = datetime.now(timezone.utc).isoformat()

        report: Dict[str, Any] = {
            "session_id": self.session.session_id,
            "started_at": self.session.started_at,
            "finished_at": self.session.finished_at,
            "repo": _drop_none(RepoInfo(
                owner=repo["owner"], name=repo["name"], ref=used_ref, commit=commit_sha
            ).__dict__),
            "stats": _drop_none(stats.__dict__),
            # IMPORTANT: drop None-valued optional fields in each finding
            "findings": [_drop_none(f.__dict__.copy()) for f in findings],
            "classification": classification,
            "summary": summary,
            "policy_flags": [],
        }

        # Final deep sanitize (defensive)
        return _sanitize(report)

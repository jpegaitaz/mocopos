# src/mocopos/core/workflow.py
from __future__ import annotations

import fnmatch
import io
import os
import sys
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import requests

from mocopos.analysis.classifier import classify
from mocopos.config.loader import Settings
from mocopos.connectors.github_client import GithubClient
from mocopos.core.result_types import Finding, RepoInfo, Stats
from mocopos.core.session import Session
from mocopos.scanning.runner import ScannerRunner

# --- Policy knobs (env) ------------------------------------------------------

# Prefer archive; optionally forbid API mode entirely.
ARCHIVE_ONLY = os.getenv("MOCOPOS_ARCHIVE_ONLY", "0") == "1"
STRICT_ARCHIVE = os.getenv("MOCOPOS_STRICT_ARCHIVE", "0") == "1"  # same behavior; alias

# If we must fall back to API mode, clamp blast radius.
MAX_API_BLOBS_PER_REPO = int(os.getenv("MOCOPOS_MAX_API_BLOBS_PER_REPO", "150"))
API_WORKERS = max(1, int(os.getenv("MOCOPOS_API_WORKERS", "4")))

# Archive streaming cap (MiB) to avoid huge downloads.
MAX_ARCHIVE_MB = int(os.getenv("MOCOPOS_MAX_ARCHIVE_MB", "150"))
MAX_ARCHIVE_BYTES = MAX_ARCHIVE_MB * 1024 * 1024

# --- Allowed "code" extensions when no includes are provided -----------------
ALLOWED_CODE_EXTS = {
    ".py", ".ts", ".tsx", ".js", ".jsx",
    ".go", ".rs", ".java", ".kt", ".swift", ".scala",
    ".c", ".cpp", ".h", ".hpp", ".cs",
    ".rb", ".php",
    ".sh", ".bash", ".zsh", ".ps1",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
}

# --- Helpers -----------------------------------------------------------------

def _log(msg: str) -> None:
    sys.stderr.write(f"[workflow] {msg}\n")
    sys.stderr.flush()

def _has_allowed_ext(path: str) -> bool:
    _, ext = os.path.splitext(path.lower())
    return ext in ALLOWED_CODE_EXTS

def _drop_none(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}

def _sanitize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_sanitize(v) for v in obj if v is not None]
    return obj

def _matches_globs_or_code_exts(path: str, includes: List[str], excludes: List[str]) -> bool:
    # excludes always apply
    if excludes and any(fnmatch.fnmatch(path, g) for g in excludes):
        return False
    # includes win if present
    if includes:
        return any(fnmatch.fnmatch(path, g) for g in includes)
    # otherwise only scan code-ish files
    return _has_allowed_ext(path)

# --- Internal exceptions ------------------------------------------------------

class ArchiveTooLarge(Exception):
    pass

class ArchiveDownloadError(Exception):
    pass

# --- Workflow ----------------------------------------------------------------

class Workflow:
    def __init__(self, settings: Settings, session: Session):
        self.settings = settings
        self.session = session

    # ------------------------- Archive Path -------------------------

    def _scan_from_archive(
        self,
        gh: GithubClient,
        owner: str,
        name: str,
        commit_sha: str,
        runner: ScannerRunner,
        max_bytes: int,
        include_globs: List[str],
        exclude_globs: List[str],
    ) -> Tuple[int, int, List[Finding]]:
        """
        Download the repo zipball once (streamed & size-bounded) and scan files locally.
        Returns: (files_scanned, total_bytes_scanned, findings)
        """
        findings: List[Finding] = []
        files_scanned = 0
        bytes_scanned = 0

        # Client-provided iterator (ideal: 1 request, 0 per-file calls)
        if hasattr(gh, "iter_archive_files"):
            for path, content_bytes in gh.iter_archive_files(owner, name, commit_sha):
                if not path:
                    continue
                if len(content_bytes) > max_bytes:
                    continue
                if not _matches_globs_or_code_exts(path, include_globs, exclude_globs):
                    continue
                try:
                    content = content_bytes.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                files_scanned += 1
                bytes_scanned += len(content_bytes)
                findings.extend(runner.scan_file(path=path, content=content))
            return files_scanned, bytes_scanned, findings

        # Generic zipball path (redirects to codeload)
        zip_url = f"{gh.api_base}/repos/{owner}/{name}/zipball/{commit_sha}"
        try:
            with requests.get(zip_url, headers=gh._headers(), stream=True, timeout=30) as resp:
                resp.raise_for_status()

                # Pre-check size if available
                clen = resp.headers.get("Content-Length")
                if clen and int(clen) > MAX_ARCHIVE_BYTES:
                    raise ArchiveTooLarge(f"zip size {int(clen)} > cap {MAX_ARCHIVE_BYTES}")

                # Stream to spooled temp (spills to disk after threshold)
                with tempfile.SpooledTemporaryFile(max_size=MAX_ARCHIVE_BYTES) as tmp:
                    total = 0
                    for chunk in resp.iter_content(chunk_size=256 * 1024):
                        if not chunk:
                            continue
                        total += len(chunk)
                        if total > MAX_ARCHIVE_BYTES:
                            raise ArchiveTooLarge(f"streamed {total} > cap {MAX_ARCHIVE_BYTES}")
                        tmp.write(chunk)

                    tmp.seek(0)
                    with zipfile.ZipFile(tmp) as zf:
                        for zi in zf.infolist():
                            if zi.is_dir():
                                continue
                            if zi.file_size > max_bytes:
                                continue

                            parts = zi.filename.split("/", 1)
                            rel = parts[1] if len(parts) > 1 else parts[0]
                            if not rel:
                                continue
                            if not _matches_globs_or_code_exts(rel, include_globs, exclude_globs):
                                continue

                            try:
                                with zf.open(zi, "r") as fh:
                                    raw = fh.read()
                            except Exception:
                                continue
                            try:
                                content = raw.decode("utf-8", errors="ignore")
                            except Exception:
                                continue

                            files_scanned += 1
                            bytes_scanned += len(raw)
                            findings.extend(runner.scan_file(path=rel, content=content))

        except ArchiveTooLarge:
            raise
        except requests.HTTPError as e:
            # Let caller decide fallback (rate/abuse/etc.)
            raise e
        except Exception as e:
            # Network/zip parse/IO errors -> fallback decision in caller
            raise ArchiveDownloadError(str(e)) from e

        return files_scanned, bytes_scanned, findings

    # --------------------------- API Path ---------------------------

    def _scan_via_api(
        self,
        gh: GithubClient,
        owner: str,
        name: str,
        commit_sha: str,
        runner: ScannerRunner,
        max_bytes: int,
        include_globs: List[str],
        exclude_globs: List[str],
    ) -> Tuple[int, int, List[Finding]]:
        """
        Walk the tree via API and fetch each blob (rate-limited & capped).
        Returns: (files_scanned, total_bytes_scanned, findings)
        """
        findings: List[Finding] = []
        bytes_scanned = 0

        # Cheap: list tree (1 call)
        files = gh.fetch_tree(owner=owner, name=name, commit=commit_sha)

        # Filter BEFORE fetching bodies
        targets = [
            f for f in files
            if f.get("type") == "blob"
            and f.get("size", 0) <= max_bytes
            and _matches_globs_or_code_exts(f.get("path", ""), include_globs, exclude_globs)
        ]

        if not targets:
            return 0, 0, findings

        # Cap how many blobs we will fetch to protect core quota
        capped = targets[:MAX_API_BLOBS_PER_REPO]
        if len(targets) > len(capped):
            _log(f"api mode capped files: {len(capped)}/{len(targets)} (MOCOPOS_MAX_API_BLOBS_PER_REPO={MAX_API_BLOBS_PER_REPO})")

        # Re-check rate limit right before we start pulling blobs
        try:
            r = gh._request("GET", f"{gh.api_base}/rate_limit", tries=1)
            rem = int(r.json().get("resources", {}).get("core", {}).get("remaining", 0))
        except Exception:
            rem = 0  # be conservative if unknown

        # Need at least N+small buffer (list tree already consumed 1)
        needed = len(capped) + 5
        if rem < needed:
            raise RuntimeError(
                f"Not enough core quota for API scan: remaining={rem} needed≈{needed}. "
                f"Use archive mode or wait for reset."
            )

        def fetch_and_scan(pth: str) -> Tuple[int, List[Finding]]:
            content = gh.fetch_blob_content(owner=owner, name=name, path=pth)
            b = len(content.encode("utf-8", errors="ignore"))
            return b, runner.scan_file(path=pth, content=content)

        files_scanned = len(capped)
        with ThreadPoolExecutor(max_workers=API_WORKERS) as ex:
            futs = {ex.submit(fetch_and_scan, f["path"]): f["path"] for f in capped}
            for fut in as_completed(futs):
                b, fnds = fut.result()
                bytes_scanned += b
                findings.extend(fnds)

        return files_scanned, bytes_scanned, findings

    # ----------------------------- Run -----------------------------

    def run(
        self,
        repo_url: str,
        ref: str | None,
        include_globs: List[str] | None = None,
        exclude_globs: List[str] | None = None,
    ) -> Dict[str, Any]:
        gh = GithubClient(api_base=self.settings.github.api_base)
        repo = gh.parse_repo_url(repo_url)

        # Fast auth/rate sanity check (401 immediately on bad token)
        try:
            gh._request("GET", f"{gh.api_base}/rate_limit", tries=1)
        except Exception as e:
            raise RuntimeError(f"GitHub auth/rate pre-check failed: {e}") from e

        # Resolve ref
        commit_sha, used_ref = gh.resolve_ref(repo["owner"], repo["name"], ref)

        # Compose globs
        include = include_globs or []
        exclude = exclude_globs if exclude_globs is not None else self.settings.scanner.ignore_globs

        # Scanner runner
        runner = ScannerRunner(
            max_bytes=self.settings.scanner.max_bytes_per_file,
            github=gh,
            owner=repo["owner"],
            name=repo["name"],
            ignore_globs=exclude,
            include_globs=include,
        )

        # Prefer archive first; allow env to force archive-only
        prefer_archive = True
        if ARCHIVE_ONLY or STRICT_ARCHIVE:
            _log("archive-only mode enabled (MOCOPOS_ARCHIVE_ONLY/STRICT_ARCHIVE)")
            prefer_archive = True

        findings: List[Finding] = []
        bytes_scanned = 0
        files_scanned = 0

        def _do_archive():
            return self._scan_from_archive(
                gh, repo["owner"], repo["name"], commit_sha, runner,
                self.settings.scanner.max_bytes_per_file, include, exclude
            )

        def _do_api():
            return self._scan_via_api(
                gh, repo["owner"], repo["name"], commit_sha, runner,
                self.settings.scanner.max_bytes_per_file, include, exclude
            )

        # Execute preferred path; only flip to API if allowed and safe.
        try:
            files_scanned, bytes_scanned, findings = _do_archive()
        except (ArchiveTooLarge, ArchiveDownloadError, requests.HTTPError) as e1:
            if ARCHIVE_ONLY or STRICT_ARCHIVE:
                raise RuntimeError(f"archive-only scan failed: {e1!r}") from e1

            _log(f"archive path failed ({e1}); considering API fallback…")
            try:
                files_scanned, bytes_scanned, findings = _do_api()
            except Exception as e2:
                raise RuntimeError(
                    f"scan failed: preferred=archive err1={e1!r} fallback(api) err2={e2!r}"
                ) from e2

        # Assemble stats and classification
        stats = Stats(
            files_scanned=files_scanned,
            bytes_scanned=bytes_scanned,
            scanners_used=runner.scanners_used(),
        )
        classification, summary = classify(findings)

        self.session.finished_at = datetime.now(timezone.utc).isoformat()

        report: Dict[str, Any] = {
            "session_id": self.session.session_id,
            "started_at": self.session.started_at,
            "finished_at": self.session.finished_at,
            "repo": _drop_none(
                RepoInfo(
                    owner=repo["owner"], name=repo["name"], ref=used_ref, commit=commit_sha
                ).__dict__
            ),
            "stats": _drop_none(stats.__dict__),
            "findings": [_drop_none(f.__dict__.copy()) for f in findings],
            "classification": classification,
            "summary": summary,
            "policy_flags": [],
        }

        return _sanitize(report)

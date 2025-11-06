from __future__ import annotations

import base64
import io
import os
import re
import sys
import time
import zipfile
import random
import threading
from typing import Dict, List, Tuple, Optional, Iterable

import requests


class GithubClient:
    """
    GitHub REST client with:
      - Per-scope pacer (min-interval) to prevent bursts
      - Small token buckets to smooth concurrency
      - Exponential backoff on 403/429 and abuse-detection responses
      - Header-aware sleeping (Retry-After, X-RateLimit-Reset)
      - Optional token pool (GITHUB_TOKENS) with automatic rotation
      - Archive iterator that prefers unauthenticated codeload for public repos
    """

    def __init__(self, api_base: str = "https://api.github.com"):
        self.api_base = api_base.rstrip("/")

        # --- Token(s) ---
        toks = os.getenv("GITHUB_TOKENS")
        if toks:
            self._tokens: List[str] = [t.strip() for t in toks.split(",") if t.strip()]
        else:
            one = os.getenv("GITHUB_TOKEN", "").strip()
            self._tokens = [one] if one else []

        self._token_idx = 0
        self._token_lock = threading.Lock()
        self._token_state: List[Dict[str, Dict[str, float]]] = [
            {"core": {"remaining": float("inf"), "reset": 0.0},
             "search": {"remaining": float("inf"), "reset": 0.0}}
            for _ in self._tokens
        ]

        self._session = requests.Session()
        self._timeout = float(os.getenv("GITHUB_TIMEOUT", "15"))

        # ---- Pacing knobs (env) ----
        # Core: 1 rps ~= 3600/hr (safe under 5000/hr)
        core_rps = float(os.getenv("MOCOPOS_CORE_RPS", "1.0"))
        # Search: limit is 30/min; keep headroom
        search_rps = float(os.getenv("MOCOPOS_SEARCH_RPS", "0.4"))
        # Small capacity prevents large bursts with many threads
        bucket_cap = float(os.getenv("MOCOPOS_BUCKET_CAP", "3"))

        now = time.time()
        self._rps = {"core": max(0.05, core_rps), "search": max(0.05, search_rps)}
        self._min_interval = {scope: 1.0 / rps for scope, rps in self._rps.items()}
        self._last_req_at = {"core": 0.0, "search": 0.0}

        # --- Client-side token buckets (small caps; refill at our chosen rps) ---
        self._buckets = {
            "core": {
                "capacity": bucket_cap,
                "tokens": bucket_cap,
                "refill_rate": self._rps["core"],  # tokens per second
                "last_refill": now,
                "lock": threading.Lock(),
            },
            "search": {
                "capacity": bucket_cap,
                "tokens": bucket_cap,
                "refill_rate": self._rps["search"],
                "last_refill": now,
                "lock": threading.Lock(),
            },
        }

    # ------------------------- Logging -------------------------

    def _log(self, msg: str) -> None:
        sys.stderr.write(f"[github] {msg}\n")
        sys.stderr.flush()

    # ------------------------- Token helpers -------------------------

    def _current_token(self) -> Optional[str]:
        if not self._tokens:
            return None
        with self._token_lock:
            return self._tokens[self._token_idx]

    def _rotate_token(self) -> None:
        if not self._tokens:
            return
        with self._token_lock:
            self._token_idx = (self._token_idx + 1) % len(self._tokens)
            cur = self._tokens[self._token_idx]
            self._log(f"rotated token → index {self._token_idx} ({'***' if cur else 'no token'})")

    def _maybe_rotate_on_exhaustion(self, scope: str, resp: requests.Response) -> None:
        """When a token hits remaining==0, rotate to next (if pool present)."""
        if not self._tokens:
            return
        try:
            rem = int(resp.headers.get("X-RateLimit-Remaining", "1"))
            rst = float(resp.headers.get("X-RateLimit-Reset", "0") or 0)
        except Exception:
            return
        with self._token_lock:
            idx = self._token_idx
            self._token_state[idx][scope]["remaining"] = rem
            self._token_state[idx][scope]["reset"] = rst
            if rem == 0 and len(self._tokens) > 1:
                self._rotate_token()

    # ------------------------- Utilities -------------------------

    def _headers(self) -> Dict[str, str]:
        hdr = {"Accept": "application/vnd.github+json"}
        tok = self._current_token()
        if tok:
            hdr["Authorization"] = f"Bearer {tok}"
        return hdr

    @staticmethod
    def parse_repo_url(url: str) -> Dict[str, str]:
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", url)
        if not m:
            raise ValueError("Invalid GitHub repository URL")
        return {"owner": m.group(1), "name": m.group(2)}

    @staticmethod
    def _scope_for(url: str) -> str:
        return "search" if "/search/" in url else "core"

    # --------------------- Client-side pacing --------------------

    def _pacer(self, scope: str) -> None:
        """Hard min-interval pacer: ensure at most RPS per scope (no bursts)."""
        min_interval = self._min_interval[scope]
        b = self._buckets[scope]
        with b["lock"]:
            now = time.time()
            elapsed = now - self._last_req_at[scope]
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
                now = time.time()
            self._last_req_at[scope] = now

    def _refill_and_take(self, scope: str) -> None:
        """Refill bucket by elapsed time and take 1 token (blocks if needed)."""
        b = self._buckets[scope]
        with b["lock"]:
            now = time.time()
            elapsed = now - b["last_refill"]
            if elapsed > 0:
                b["tokens"] = min(b["capacity"], b["tokens"] + elapsed * b["refill_rate"])
                b["last_refill"] = now
            if b["tokens"] >= 1.0:
                b["tokens"] -= 1.0
                return
            needed = 1.0 - b["tokens"]
            wait = max(0.0, needed / b["refill_rate"]) if b["refill_rate"] > 0 else 1.0
            time.sleep(wait)
            now = time.time()
            elapsed = now - b["last_refill"]
            if elapsed > 0:
                b["tokens"] = min(b["capacity"], b["tokens"] + elapsed * b["refill_rate"])
                b["last_refill"] = now
            b["tokens"] = max(0.0, b["tokens"] - 1.0)

    def _update_bucket_from_headers(self, scope: str, resp: requests.Response) -> None:
        """
        Reflect remaining into current token count, but keep small capacity and
        our chosen refill rate (so we don't re-enable bursts).
        """
        try:
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if remaining is None:
                return
            rem = float(remaining)
            b = self._buckets[scope]
            with b["lock"]:
                b["tokens"] = max(0.0, min(b["capacity"], rem))
                b["last_refill"] = time.time()
        except Exception:
            pass

    def _respect_headers_sleep(self, resp: requests.Response) -> bool:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                secs = min(float(retry_after), 30.0)
                self._log(f"Retry-After={secs:.1f}s")
                time.sleep(secs)
                return True
            except Exception:
                pass
        rem = resp.headers.get("X-RateLimit-Remaining")
        reset = resp.headers.get("X-RateLimit-Reset")
        if rem == "0" and reset:
            try:
                reset_epoch = float(reset)
                now = time.time()
                sleep_for = max(1.0, reset_epoch - now)
                sleep_for = min(sleep_for, 60.0)
                self._log(f"Rate limit hit; sleeping {sleep_for:.1f}s")
                time.sleep(sleep_for)
                return True
            except Exception:
                pass
        return False

    # --------------------- Centralized request -------------------

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        tries: int = 5,
        base_backoff: float = 1.4,
        jitter: float = 0.3,
    ) -> requests.Response:
        scope = self._scope_for(url)
        hdrs = self._headers()
        if headers:
            hdrs.update(headers)

        last_exc: Optional[Exception] = None

        for attempt in range(tries):
            # Enforce hard pacing first (no bursts), then token smoothing.
            self._pacer(scope)
            self._refill_and_take(scope)

            try:
                resp = self._session.request(
                    method, url, params=params, headers=hdrs, timeout=self._timeout
                )
            except Exception as e:
                last_exc = e
                sleep = min(1.0 + attempt * 0.5, 3.0)
                self._log(f"network error: {e!r}; retry in {sleep:.1f}s")
                time.sleep(sleep)
                continue

            self._update_bucket_from_headers(scope, resp)
            self._maybe_rotate_on_exhaustion(scope, resp)

            # explicit fatal on 401
            if resp.status_code == 401:
                try:
                    msg = resp.json().get("message", "")
                except Exception:
                    msg = resp.text
                raise requests.HTTPError(f"401 Unauthorized: {msg or 'Bad credentials'}", response=resp)

            if resp.status_code < 400:
                return resp

            if resp.status_code in (403, 429):
                if self._respect_headers_sleep(resp):
                    continue
                try:
                    txt = (resp.json().get("message", "") or resp.text or "").lower()
                except Exception:
                    txt = (resp.text or "").lower()

                if "abuse" in txt or "rate limit" in txt:
                    sleep = min((base_backoff ** attempt) + random.uniform(0, jitter), 8.0)
                    self._log(f"{resp.status_code} backoff {sleep:.1f}s ({txt[:60]}...)")
                    time.sleep(sleep)
                    continue

            if 500 <= resp.status_code < 600 and attempt < tries - 1:
                sleep = min(1.0 + attempt * 0.7, 4.0)
                self._log(f"{resp.status_code} server err; retry in {sleep:.1f}s")
                time.sleep(sleep)
                continue

            try:
                resp.raise_for_status()
            except requests.HTTPError as e:
                last_exc = e
                break

        if last_exc:
            raise last_exc
        raise RuntimeError(f"GitHub request failed after {tries} attempts: {method} {url}")

    # ------------------------ Public API -------------------------

    def resolve_ref(self, owner: str, name: str, ref: str | None) -> Tuple[str, str]:
        if ref:
            r = self._request("GET", f"{self.api_base}/repos/{owner}/{name}/git/refs/heads/{ref}")
            if r.status_code == 200:
                return r.json()["object"]["sha"], ref
            r = self._request("GET", f"{self.api_base}/repos/{owner}/{name}/git/refs/tags/{ref}")
            r.raise_for_status()
            return r.json()["object"]["sha"], ref

        repo = self._request("GET", f"{self.api_base}/repos/{owner}/{name}")
        repo.raise_for_status()
        default_branch = repo.json()["default_branch"]

        branch = self._request("GET", f"{self.api_base}/repos/{owner}/{name}/branches/{default_branch}")
        branch.raise_for_status()
        return branch.json()["commit"]["sha"], default_branch

    def fetch_tree(self, owner: str, name: str, commit: str) -> List[Dict]:
        r = self._request(
            "GET",
            f"{self.api_base}/repos/{owner}/{name}/git/trees/{commit}",
            params={"recursive": "1"},
        )
        r.raise_for_status()
        tree = r.json().get("tree", [])
        files: List[Dict] = []
        for node in tree:
            if node.get("type") == "blob":
                files.append({"path": node["path"], "type": "blob", "size": node.get("size", 0)})
        return files

    def fetch_blob_content(self, owner: str, name: str, path: str) -> str:
        r = self._request("GET", f"{self.api_base}/repos/{owner}/{name}/contents/{path}")
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and data.get("encoding") == "base64" and "content" in data:
            b64 = (data["content"] or "").encode("utf-8")
            try:
                decoded = base64.b64decode(b64, validate=False)
                return decoded.decode("utf-8", errors="ignore")
            except Exception:
                try:
                    decoded = base64.b64decode(b64.replace(b"\n", b""))
                    return decoded.decode("utf-8", errors="ignore")
                except Exception:
                    return ""
        if isinstance(data, dict) and "content" in data and data.get("encoding") is None:
            try:
                return str(data["content"])
            except Exception:
                return ""
        return ""

    def search_repositories(
        self,
        q: str,
        per_page: int = 10,
        pages: int = 1,
        min_stars: int | None = None,
        max_results: int | None = None,
        page_start: int = 1,
    ) -> List[Dict]:
        """
        Search GitHub repositories.
        Returns list of dicts:
          {owner, name, full_name, html_url, stargazers_count, default_branch}
        """
        results: List[Dict] = []
        page = max(1, page_start)
        fetched = 0
        max_total = max_results if max_results is not None else float("inf")

        while page < page_start + max(1, pages) and fetched < max_total:
            params = {
                "q": q,
                "sort": "stars",
                "order": "desc",
                "per_page": max(1, min(per_page, 100)),
                "page": page,
            }
            r = self._request("GET", f"{self.api_base}/search/repositories", params=params)
            r.raise_for_status()
            data = r.json()
            items = data.get("items", [])

            for it in items:
                if fetched >= max_total:
                    break
                stars = it.get("stargazers_count", 0)
                if min_stars is not None and stars < min_stars:
                    continue
                full_name = it.get("full_name", "") or ""
                if "/" in full_name:
                    owner, name = full_name.split("/", 1)
                else:
                    owner = (it.get("owner") or {}).get("login", "")
                    name = it.get("name", "")
                results.append({
                    "owner": owner,
                    "name": name,
                    "full_name": full_name or f"{owner}/{name}",
                    "html_url": it.get("html_url", ""),
                    "stargazers_count": stars,
                    "default_branch": it.get("default_branch", "main"),
                })
                fetched += 1

            if len(items) < params["per_page"]:
                break
            page += 1

        return results

    # -------------------- Archive iterator ----------------------

    def iter_archive_files(self, owner: str, name: str, commit: str) -> Iterable[Tuple[str, bytes]]:
        """
        Yield (repo_relative_path, content_bytes) from a zip archive of the repo at `commit`.

        - Try unauthenticated codeload (public repos; saves core quota):
          https://codeload.github.com/{owner}/{name}/zip/{commit}
        - Fall back to authenticated API zipball if codeload fails:
          {api_base}/repos/{owner}/{name}/zipball/{commit}
        """
        codeload = f"https://codeload.github.com/{owner}/{name}/zip/{commit}"
        try:
            r = requests.get(codeload, stream=True, timeout=self._timeout)
            if r.status_code == 200:
                data = r.content
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for zi in zf.infolist():
                        if zi.is_dir():
                            continue
                        parts = zi.filename.split("/", 1)
                        rel = parts[1] if len(parts) > 1 else parts[0]
                        if not rel:
                            continue
                        with zf.open(zi, "r") as fh:
                            yield rel, fh.read()
                return
        except Exception as e:
            self._log(f"codeload failed, will fall back: {e!r}")

        zip_url = f"{self.api_base}/repos/{owner}/{name}/zipball/{commit}"
        r = self._request("GET", zip_url, headers=self._headers())
        r.raise_for_status()
        data = r.content
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for zi in zf.infolist():
                if zi.is_dir():
                    continue
                parts = zi.filename.split("/", 1)
                rel = parts[1] if len(parts) > 1 else parts[0]
                if not rel:
                    continue
                with zf.open(zi, "r") as fh:
                    yield rel, fh.read()

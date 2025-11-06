# src/mocopos/cli/discover.py
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any, Iterable

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from mocopos.config.loader import Settings
from mocopos.core.session import Session
from mocopos.core.workflow import Workflow
from mocopos.connectors.github_client import GithubClient

console = Console()


@dataclass
class RepoEntry:
    owner: str
    name: str
    full_name: str
    html_url: str
    stargazers_count: int
    default_branch: str


@dataclass
class RepoSummary:
    owner: str
    name: str
    stars: int
    classification: str
    findings: int
    files_scanned: int
    bytes_scanned: int


def _class_rank(c: str) -> int:
    return {"Threat": 3, "Potential Threat": 2, "Safe": 1, "Unscanned": 0, "Error": 0}.get(c, 0)


def _chunked(seq: List[RepoEntry], size: int) -> Iterable[List[RepoEntry]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def _print_repo_list(repos: List[RepoEntry]) -> None:
    table = Table(title=f"Discovered Repositories ({len(repos)})")
    table.add_column("#", justify="right")
    table.add_column("Repository")
    table.add_column("Stars", justify="right")
    table.add_column("URL")
    for i, r in enumerate(repos, start=1):
        table.add_row(str(i), r.full_name, str(r.stargazers_count), r.html_url)
    console.print(table)


def _load_seen(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    seen: set[str] = set()
    if isinstance(data, list):
        for it in data:
            owner, name = it.get("owner"), it.get("name")
            if owner and name:
                seen.add(f"{owner}/{name}")
    elif isinstance(data, dict):
        for it in data.get("results", []):
            repo = it.get("repo", {})
            owner, name = repo.get("owner"), repo.get("name")
            if owner and name:
                seen.add(f"{owner}/{name}")
        for it in data.get("repos", []):
            owner, name = it.get("owner"), it.get("name")
            if owner and name:
                seen.add(f"{owner}/{name}")
    return seen


def _rate_status(gh: GithubClient) -> tuple[int, int, float]:
    """return (remaining, limit, reset_epoch) for core scope; fallback to conservative."""
    try:
        r = gh._request("GET", f"{gh.api_base}/rate_limit", tries=1)
        core = (r.json().get("resources", {}) or {}).get("core", {}) or {}
        return int(core.get("remaining", 0)), int(core.get("limit", 5000)), float(
            core.get("reset", time.time() + 3600)
        )
    except Exception:
        now = time.time()
        return 0, 5000, now + 900


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option(
    "--query",
    "-q",
    type=str,
    default="mcp server",
    show_default=True,
    help="GitHub search query for repositories.",
)
@click.option("--pages", type=int, default=1, show_default=True, help="Number of pages to fetch.")
@click.option(
    "--page-start", type=int, default=1, show_default=True, help="Start fetching at this page number (1-based)."
)
@click.option("--per-page", type=int, default=10, show_default=True, help="Repositories per page (max 100).")
@click.option("--min-stars", type=int, default=None, help="Filter out repos with fewer than this many stars.")
@click.option("--max-results", type=int, default=None, help="Hard cap on number of repos to collect (across all pages).")
@click.option("--list-only", is_flag=True, default=False, help="Only list found repositories; do not scan.")
@click.option("--print-repos", is_flag=True, default=False, help="Print the repository list before scanning.")
@click.option(
    "--save-repos",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Save discovered repo list to this JSON file.",
)
@click.option(
    "--from-file",
    "from_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Load repo list from a JSON file (skips live search).",
)
@click.option(
    "--skip-from",
    "skip_from",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Skip repos found in this JSON (aggregate or repo list).",
)
@click.option("--resume", type=int, default=0, show_default=True, help="Skip the first N repos from the current list.")
@click.option("--batch-size", type=int, default=10, show_default=True, help="Scan this many repos per batch.")
@click.option("--sleep-seconds", type=float, default=5.0, show_default=True, help="Pause between batches (seconds).")
@click.option(
    "--workers",
    type=int,
    default=1,
    show_default=True,
    help="Max concurrent scans per batch. Use 1 to minimize rate bursts.",
)
@click.option(
    "--per-repo-delay",
    type=float,
    default=1.2,
    show_default=True,
    help="Sleep this many seconds after EACH repo completes (extra pacing).",
)
@click.option(
    "--rate-floor",
    type=int,
    default=50,
    show_default=True,
    help="If core remaining falls below this, wait until reset between batches.",
)
@click.option(
    "--include",
    "include_globs",
    type=str,
    default=None,
    help="Comma-separated globs to FORCE include when scanning (e.g., 'src/**,**/*.py').",
)
@click.option(
    "--exclude",
    "exclude_globs",
    type=str,
    default=None,
    help="Comma-separated globs to exclude (overrides config ignores).",
)
@click.option("--progress/--no-progress", default=True, show_default=True, help="Show live progress bars while scanning.")
@click.option(
    "--per-repo-timeout",
    type=float,
    default=300.0,
    show_default=True,
    help="Fail a repo if it takes longer than this many seconds.",
)
@click.option(
    "--out",
    "out_path",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Write aggregated JSON to this path.",
)
def main(
    query: str,
    pages: int,
    page_start: int,
    per_page: int,
    min_stars: Optional[int],
    max_results: Optional[int],
    list_only: bool,
    print_repos: bool,
    save_repos: Optional[Path],
    from_file: Optional[Path],
    skip_from: Optional[Path],
    resume: int,
    batch_size: int,
    sleep_seconds: float,
    workers: int,
    progress: bool,
    per_repo_timeout: float,
    per_repo_delay: float,
    rate_floor: int,
    include_globs: Optional[str],
    exclude_globs: Optional[str],
    out_path: Optional[Path],
) -> None:
    """
    Search GitHub and batch-scan with conservative rate pacing.
    """
    load_dotenv()
    settings = Settings.load()
    gh = GithubClient(api_base=settings.github.api_base)

    repos: List[RepoEntry] = []
    if from_file:
        data = json.loads(from_file.read_text(encoding="utf-8"))
        for it in data:
            repos.append(
                RepoEntry(
                    owner=it["owner"],
                    name=it["name"],
                    full_name=it.get("full_name", f'{it["owner"]}/{it["name"]}'),
                    html_url=it.get("html_url", f'https://github.com/{it["owner"]}/{it["name"]}'),
                    stargazers_count=int(it.get("stargazers_count", 0)),
                    default_branch=it.get("default_branch", "main"),
                )
            )
        console.print(f"[bold]Loaded repositories from file:[/bold] {from_file} ({len(repos)})")
    else:
        console.print(
            f"[bold]Searching GitHub:[/bold] '{query}' (page_start={page_start}, pages={pages}, per_page={per_page})"
        )
        found = gh.search_repositories(
            q=query, per_page=per_page, pages=pages, min_stars=min_stars, max_results=max_results, page_start=page_start
        )
        for it in found:
            repos.append(
                RepoEntry(
                    owner=it["owner"],
                    name=it["name"],
                    full_name=it["full_name"],
                    html_url=it["html_url"],
                    stargazers_count=it["stargazers_count"],
                    default_branch=it["default_branch"],
                )
            )
        console.print(f"[bold]Found repos:[/bold] {len(repos)}")

    if skip_from:
        seen = _load_seen(skip_from)
        before = len(repos)
        repos = [r for r in repos if f"{r.owner}/{r.name}" not in seen]
        console.print(
            f"[bold]Skipping already-seen repos from:[/bold] {skip_from}  (filtered {before - len(repos)} of {before})"
        )

    if resume > 0:
        before = len(repos)
        repos = repos[resume:]
        console.print(f"[bold]Resuming after {resume} repos[/bold] (remaining {len(repos)} of {before})")

    if save_repos:
        serializable = [r.__dict__ for r in repos]
        save_repos.write_text(json.dumps(serializable, indent=2), encoding="utf-8")
        console.print(f"[green]Saved repository list to:[/green] {save_repos.resolve()}")

    if print_repos or list_only:
        _print_repo_list(repos)
    if list_only:
        return

    # IMPORTANT:
    # - Only pass include_globs if user provided --include.
    # - Only pass exclude_globs if user provided --exclude.
    #   If not provided, we *must* leave it as None so Settings (incl. .mocoposignore)
    #   supply the default ignore set and avoid scanning lockfiles etc.
    include: Optional[List[str]] = (
        [v.strip() for v in (include_globs or "").split(",") if v.strip()] if include_globs else None
    )
    exclude: Optional[List[str]] = (
        [v.strip() for v in (exclude_globs or "").split(",") if v.strip()] if exclude_globs else None
    )

    batch_size = max(1, batch_size)
    workers = max(1, min(workers, batch_size))
    results: List[Dict[str, Any]] = []

    partial_out: Optional[Path] = None
    if out_path:
        partial_out = out_path.with_suffix(out_path.suffix + ".partial.jsonl")
        partial_out.write_text("", encoding="utf-8")

    def _write_partial(res: Dict[str, Any]) -> None:
        if not partial_out:
            return
        with partial_out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(res, ensure_ascii=False) + "\n")

    def scan_repo(owner: str, name: str) -> Dict[str, Any]:
        repo_url = f"https://github.com/{owner}/{name}"
        session = Session(session_id=f"batch-{owner}-{name}", started_at="")
        wf = Workflow(settings=settings, session=session)
        try:
            res = wf.run(repo_url=repo_url, ref=None, include_globs=include, exclude_globs=exclude)
            res.setdefault("status", "ok")
            if res.get("stats", {}).get("files_scanned", 0) == 0 and not res.get("findings"):
                res.setdefault("classification", "Unscanned")
            return res
        except Exception as e:
            return {
                "session_id": session.session_id,
                "repo": {"owner": owner, "name": name, "ref": "?", "commit": "?"},
                "stats": {"files_scanned": 0, "bytes_scanned": 0, "scanners_used": []},
                "findings": [],
                "classification": "Error",
                "summary": f"Scan error: {e}",
                "status": "error",
            }

    try:
        # Show starting rate
        remaining, limit, reset_epoch = _rate_status(gh)
        console.print(
            f"[dim]Rate start: core {remaining}/{limit}; reset @ {time.strftime('%H:%M:%S', time.localtime(reset_epoch))}[/dim]"
        )

        for batch_index, group in enumerate(_chunked(repos, batch_size), start=1):
            console.rule(f"[bold]Batch {batch_index}[/bold] ({len(group)} repos)")

            # Before each batch, if dangerously low, sleep until reset
            remaining, limit, reset_epoch = _rate_status(gh)
            if remaining <= rate_floor:
                wait_s = max(0, int(reset_epoch - time.time()))
                if wait_s > 0:
                    console.print(
                        f"[yellow]Rate low (core {remaining}/{limit}). Sleeping until reset ~ {wait_s}s.[/yellow]"
                    )
                    time.sleep(min(wait_s, 1200))  # cap 20 minutes to avoid indefinite waits in CI

            if not progress:
                queue = list(group)
                running: Dict[Any, RepoEntry] = {}
                started_at: Dict[Any, float] = {}
                with ThreadPoolExecutor(max_workers=workers) as ex:
                    while queue or running:
                        while queue and len(running) < workers:
                            r = queue.pop(0)
                            console.print(f"[dim]→ start {r.owner}/{r.name}[/dim]")
                            fut = ex.submit(scan_repo, r.owner, r.name)
                            running[fut] = r
                            started_at[fut] = time.monotonic()

                        done, _ = wait(running.keys(), timeout=0.2, return_when=FIRST_COMPLETED)

                        for f in list(done):
                            r = running.pop(f)
                            started_at.pop(f, None)
                            try:
                                res = f.result()
                            except Exception as e:
                                res = {
                                    "repo": {"owner": r.owner, "name": r.name, "ref": "?", "commit": "?"},
                                    "stats": {"files_scanned": 0, "bytes_scanned": 0, "scanners_used": []},
                                    "findings": [],
                                    "classification": "Error",
                                    "summary": f"Worker error: {e!r}",
                                    "status": "error",
                                }
                            results.append(res)
                            _write_partial(res)
                            console.print(f"[green]✓ done  {r.owner}/{r.name}[/green]")

                            # pacing: sleep after every repo
                            if per_repo_delay > 0:
                                time.sleep(per_repo_delay)

                            if queue:
                                nr = queue.pop(0)
                                console.print(f"[dim]→ start {nr.owner}/{nr.name}[/dim]")
                                nf = ex.submit(scan_repo, nr.owner, nr.name)
                                running[nf] = nr
                                started_at[nf] = time.monotonic()

                        # simple watchdog (unchanged)
                        now = time.monotonic()
                        for f, r in list(running.items()):
                            if now - started_at.get(f, now) > per_repo_timeout:
                                running.pop(f, None)
                                started_at.pop(f, None)
                                res = {
                                    "repo": {"owner": r.owner, "name": r.name, "ref": "?", "commit": "?"},
                                    "stats": {"files_scanned": 0, "bytes_scanned": 0},
                                    "findings": [],
                                    "classification": "Error",
                                    "summary": f"Timed out after {int(per_repo_timeout)}s",
                                    "status": "error",
                                }
                                results.append(res)
                                _write_partial(res)
                                console.print(
                                    f"[red]✗ timeout {r.owner}/{r.name} ({int(per_repo_timeout)}s)[/red]"
                                )

                                if queue:
                                    nr = queue.pop(0)
                                    console.print(f"[dim]→ start {nr.owner}/{nr.name}[/dim]")
                                    nf = ex.submit(scan_repo, nr.owner, nr.name)
                                    running[nf] = nr
                                    started_at[nf] = time.monotonic()
            else:
                with Progress(
                    SpinnerColumn(),
                    "[progress.description]{task.description}",
                    BarColumn(),
                    "[progress.percentage]{task.percentage:>3.0f}%",
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    transient=False,
                    console=console,
                ) as prog:
                    batch_task = prog.add_task(f"Scanning repos (batch {batch_index})", total=len(group))
                    queue = list(group)
                    running: Dict[Any, tuple[str, str]] = {}
                    repo_tasks: Dict[tuple[str, str], int] = {}
                    started_at: Dict[Any, float] = {}

                    def submit_one(r: RepoEntry):
                        key = (r.owner, r.name)
                        repo_tasks[key] = prog.add_task(f"[cyan]{r.owner}/{r.name}", total=None)
                        fut = ex.submit(scan_repo, r.owner, r.name)
                        running[fut] = key
                        started_at[fut] = time.monotonic()

                    with ThreadPoolExecutor(max_workers=workers) as ex:
                        while queue and len(running) < workers:
                            submit_one(queue.pop(0))

                        while running:
                            done, _ = wait(running.keys(), timeout=0.2, return_when=FIRST_COMPLETED)

                            for fut in list(done):
                                key = running.pop(fut)
                                started_at.pop(fut, None)
                                try:
                                    res = fut.result()
                                except Exception as e:
                                    res = {
                                        "repo": {"owner": key[0], "name": key[1], "ref": "?", "commit": "?"},
                                        "stats": {"files_scanned": 0, "bytes_scanned": 0, "scanners_used": []},
                                        "findings": [],
                                        "classification": "Error",
                                        "summary": f"Worker error: {e!r}",
                                        "status": "error",
                                    }
                                results.append(res)
                                _write_partial(res)

                                t_id = repo_tasks[key]
                                prog.update(t_id, description=f"[green]✓ {key[0]}/{key[1]}", total=1, completed=1)
                                prog.advance(batch_task, 1)

                                # pacing after each repo
                                if per_repo_delay > 0:
                                    time.sleep(per_repo_delay)

                                if queue:
                                    submit_one(queue.pop(0))

                            now = time.monotonic()
                            for fut, key in list(running.items()):
                                if now - started_at.get(fut, now) > per_repo_timeout:
                                    running.pop(fut, None)
                                    started_at.pop(fut, None)
                                    res = {
                                        "repo": {"owner": key[0], "name": key[1], "ref": "?", "commit": "?"},
                                        "stats": {"files_scanned": 0, "bytes_scanned": 0, "scanners_used": []},
                                        "findings": [],
                                        "classification": "Error",
                                        "summary": f"Timed out after {int(per_repo_timeout)}s",
                                        "status": "error",
                                    }
                                    results.append(res)
                                    _write_partial(res)

                                    t_id = repo_tasks[key]
                                    prog.update(
                                        t_id, description=f"[red]✗ {key[0]}/{key[1]} (timeout)", total=1, completed=1
                                    )
                                    prog.advance(batch_task, 1)

                                    if queue:
                                        submit_one(queue.pop(0))

            # Between batches: short pause + show current rate
            if sleep_seconds > 0 and (batch_index * batch_size) < len(repos):
                console.print(f"[dim]Sleeping {sleep_seconds:.1f}s to respect API limits...[/dim]")
                time.sleep(sleep_seconds)
            remaining, limit, reset_epoch = _rate_status(gh)
            console.print(
                f"[dim]Rate now  : core {remaining}/{limit} (reset @ {time.strftime('%H:%M:%S', time.localtime(reset_epoch))})[/dim]"
            )

    except KeyboardInterrupt:
        console.print("[yellow]\nInterrupted — writing what we have so far.[/yellow]")

    summaries: List[RepoSummary] = []
    stars_lookup = {r.full_name: r.stargazers_count for r in repos}
    for r in results:
        key = f'{r.get("repo", {}).get("owner","")}/{r.get("repo", {}).get("name","")}'
        summaries.append(
            RepoSummary(
                owner=r.get("repo", {}).get("owner", ""),
                name=r.get("repo", {}).get("name", ""),
                stars=stars_lookup.get(key, 0),
                classification=r.get("classification", "Unscanned"),
                findings=len(r.get("findings", []) or []),
                files_scanned=(r.get("stats", {}) or {}).get("files_scanned", 0),
                bytes_scanned=(r.get("stats", {}) or {}).get("bytes_scanned", 0),
            )
        )

    summaries.sort(key=lambda s: (s.findings, _class_rank(s.classification), s.stars), reverse=True)

    table = Table(title="Mocopos Leaderboard (by flagged findings)")
    table.add_column("Rank", justify="right")
    table.add_column("Repository")
    table.add_column("Class")
    table.add_column("Findings", justify="right")
    table.add_column("Files", justify="right")
    table.add_column("Stars", justify="right")
    for i, s in enumerate(summaries, start=1):
        table.add_row(str(i), f"{s.owner}/{s.name}", s.classification, str(s.findings), str(s.files_scanned), str(s.stars))
    console.print(table)

    if out_path:
        aggregate = {
            "query": f"{query}" if not from_file else f"from_file:{Path(from_file).name}",
            "page_start": page_start,
            "pages": pages,
            "per_page": per_page,
            "count": len(results),
            "repos": [r.__dict__ for r in repos],
            "leaderboard": [s.__dict__ for s in summaries],
            "results": results,
        }
        out_path.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
        console.print(f"[green]Aggregate JSON saved to:[/green] {out_path.resolve()}")
        if partial_out:
            console.print(f"[green]Partial JSONL (streaming results) at:[/green] {partial_out.resolve()}")

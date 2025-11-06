import json
import pathlib
import ast
import math
from collections import Counter, defaultdict
from typing import Dict, Any, List, Tuple, Iterable, Optional
from .openai_client import call_openai_responses
from .prompt_templates import render_system_instructions, render_batch_instructions
from .session_utils import generate_session_id, infer_session_id, stamp_prefix, utc_stamp
from .pdf_renderer import md_to_pdf



# ---------- robust parsing (unchanged logic with helpers) ----------

def _parse_obj(line: str):
    line = line.strip()
    if not line or line.startswith("//") or line.startswith("#"):
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        pass
    try:
        obj = ast.literal_eval(line)
        if isinstance(obj, (dict, list)):
            return obj
    except Exception:
        pass
    return None

def _read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")

def _load_items(filepath: pathlib.Path) -> List[Dict[str, Any]]:
    text = _read_text(filepath).strip()
    try:
        root = json.loads(text)
        if isinstance(root, dict):
            return [root]
        if isinstance(root, list):
            return [x for x in root if isinstance(x, dict)]
    except json.JSONDecodeError:
        pass
    items: List[Dict[str, Any]] = []
    for raw in text.splitlines():
        obj = _parse_obj(raw)
        if isinstance(obj, dict):
            items.append(obj)
        elif isinstance(obj, list):
            items.extend([x for x in obj if isinstance(x, dict)])
    return items

def _repo_key(obj: dict) -> str | None:
    name = _repo_display_name(obj)
    return name or None


def _merge_lists_unique(seq: Iterable[Any]) -> List[Any]:
    out, seen = [], set()
    for x in seq:
        key = json.dumps(x, sort_keys=True, ensure_ascii=False) if isinstance(x, (dict, list)) else x
        if key not in seen:
            out.append(x)
            seen.add(key)
    return out

def _merge_repo_records(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    acc: Dict[str, Any] = {"run": {}, "repo": {}, "stats": {}, "policy": {}, "flags": [], "findings": []}
    for obj in items:
        for k in ("repo", "run"):
            if obj.get(k):
                acc[k] = {**acc.get(k, {}), **obj[k]}

        # stats: sum files_scanned; we will compute flagged_count from findings if absent
        stats = obj.get("stats") or {}
        acc.setdefault("stats", {})
        for k in ("files_scanned",):
            if k in stats and isinstance(stats[k], (int, float)):
                acc["stats"][k] = int(acc["stats"].get(k, 0)) + int(stats[k])

        # accumulate findings (new schema)
        fnds = obj.get("findings") or []
        if isinstance(fnds, list):
            acc["findings"].extend([f for f in fnds if isinstance(f, dict)])

        # accumulate flags (legacy schema)
        flgs = obj.get("flags") or []
        if isinstance(flgs, list):
            acc["flags"].extend([f for f in flgs if isinstance(f, dict)])

        # policy include/exclude (optional)
        pol = obj.get("policy") or {}
        inc = pol.get("include") or []
        exc = pol.get("exclude") or []
        acc.setdefault("policy", {})
        acc["policy"]["include"] = _merge_lists_unique([*(acc["policy"].get("include") or []), *inc])
        acc["policy"]["exclude"] = _merge_lists_unique([*(acc["policy"].get("exclude") or []), *exc])

    # Dedupe
    acc["findings"] = _merge_lists_unique(acc["findings"])
    acc["flags"] = _merge_lists_unique(acc["flags"])

    # Derive flagged_count
    flagged_count = len(acc["findings"]) if acc["findings"] else len(acc["flags"])
    st = acc.setdefault("stats", {})
    st["flagged_count"] = int(st.get("flagged_count", 0)) + int(flagged_count)

    # Derive files_scanned if absent but we have safe + flagged (not used here)
    if "files_scanned" not in st and "safe_count" in st:
        st["files_scanned"] = int(st["safe_count"]) + int(st["flagged_count"])

    return acc

def _group_by_repo(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    orphans: List[Dict[str, Any]] = []
    for it in items:
        key = _repo_key(it)
        if key:
            buckets.setdefault(key, []).append(it)
        else:
            orphans.append(it)
    merged: List[Dict[str, Any]] = []
    for key, group in buckets.items():
        merged.append(_merge_repo_records(group))
    merged.extend(orphans)
    return merged

def write_batch_index(results: List[Tuple[str, pathlib.Path]], out_dir: pathlib.Path, *, session_id: str, ts: str) -> pathlib.Path:
    lines = [f"# Security Scan Reports (Batch Index) — {ts} / {session_id}\n"]
    seen = set()
    for repo_name, path in sorted(results, key=lambda x: x[0].lower()):
        rel = path.relative_to(out_dir)
        key = (repo_name, rel.as_posix())
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"- **{repo_name}** → [{rel.as_posix()}]({rel.as_posix()})")
    index_path = out_dir / f"{stamp_prefix(session_id, ts)}__INDEX.md"
    index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return index_path

def _extract_session_from_repo_obj(repo_obj: Dict[str, Any]) -> Optional[str]:
    run = repo_obj.get("run") or {}
    # Prefer explicit session_id, then run id, then config hash
    sid = run.get("session_id")
    if sid and isinstance(sid, str) and sid.strip():
        return sid.strip()
    candidates = [
        run.get("id"),
        run.get("config_hash"),
    ]
    return infer_session_id([c for c in candidates if c])

def _first_nonempty(*vals):
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None

def _repo_display_name(obj: dict) -> str:
    """
    Produce a stable repo identifier like 'owner/name'.
    Falls back to URL parsing or run.id heuristic, else 'unknown_repo'.
    """
    repo = obj.get("repo") or {}
    full = repo.get("full_name")
    owner = repo.get("owner")
    name = repo.get("name")
    html_url = repo.get("html_url") or obj.get("repo_url") or obj.get("url")

    # 1) full_name
    if full:
        return full

    # 2) owner + name
    if owner and name:
        return f"{owner}/{name}"

    # 3) alternate fields you might have
    alt_full = _first_nonempty(
        obj.get("repo_full_name"),
        obj.get("repository"),
        obj.get("project"),
    )
    if alt_full:
        if "__" in alt_full and "/" not in alt_full:
            parts = alt_full.split("__", 1)
            if len(parts) == 2:
                return f"{parts[0]}/{parts[1]}"
        return alt_full

    # 4) parse from URL
    if html_url:
        m = re.search(r"https?://[^/]+/([^/]+)/([^/]+)/?$", html_url)
        if m:
            return f"{m.group(1)}/{m.group(2)}"

    # 5) heuristic from run.id like "batch-owner-repo..."
    run = obj.get("run") or {}
    rid = (run.get("id") or obj.get("session_id") or "")
    if isinstance(rid, str) and rid:
        m2 = re.search(r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", rid)
        if m2:
            return f"{m2.group(1)}/{m2.group(2)}"
        rid2 = re.sub(r"^batch[-_]", "", rid)
        toks = [t for t in rid2.split("-") if t]
        if len(toks) >= 2:
            return f"{toks[0]}/{ '-'.join(toks[1:]) }"

    return "unknown_repo"

def _safe_report_filename(display_name: str) -> str:
    """
    Convert 'owner/name' → 'owner__name.md'. Stabilize 'unknown_repo' with a short hash.
    """
    if display_name == "unknown_repo":
        suffix = hashlib.sha1(display_name.encode("utf-8")).hexdigest()[:8]
        return f"unknown_repo_{suffix}.md"
    return f"{display_name.replace('/', '__')}.md"

# ---------- LLM I/O helpers ----------

def _build_input(repo_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    narr = [
        "Below is SCAN_RESULT, a compact JSON from mocopos scanner.",
        "Write a corporate-grade report per the instructions.",
        "If something is missing, make a conservative assumption and call it out."
    ]
    body = json.dumps(repo_obj, ensure_ascii=False)
    text = "\n".join(narr) + "\n\nSCAN_RESULT=\n" + body
    return [{"role": "user", "content": [{"type": "input_text", "text": text}]}]

def _emit_report(
    repo_obj: Dict[str, Any],
    out_dir: pathlib.Path,
    model: str,
    temperature: float,
    seed: int,
    max_output_tokens: int,
    *,
    session_id: str,
    ts: str,
    render_pdf: bool = False,
    company: str = "MOCOPOS Security",
    logo_path: Optional[str] = None,
    report_type: str = "Per-Repository",
) -> Tuple[str, pathlib.Path, Optional[pathlib.Path]]:
    display_name = _repo_display_name(repo_obj)
    out_dir.mkdir(parents=True, exist_ok=True)
    prefix = stamp_prefix(session_id, ts)
    md_name = _safe_report_filename(display_name)  # e.g., owner__repo.md
    md_path = out_dir / f"{prefix}__{md_name}"

    instructions = render_system_instructions()
    input_obj = _build_input(repo_obj)
    md = call_openai_responses(
        model=model, instructions=instructions, input_obj=input_obj,
        response_format=None, temperature=temperature, seed=seed,
        max_output_tokens=max_output_tokens,
    )
    md_path.write_text(md, encoding="utf-8")

    pdf_path = None
    if render_pdf:
        pdf_name = md_path.stem + ".pdf"
        pdf_path = md_path.with_name(pdf_name)
        meta = {
            "title": display_name,
            "subtitle": "Automated Repository Security Analysis",
            "company": company,
            "report_type": report_type,
            "timestamp": ts,
            "session_id": session_id,
            "logo_path": logo_path,
        }
        md_to_pdf(md_path, pdf_path, meta=meta)

    return display_name, md_path, pdf_path


# ---------- Batch consolidation ----------

def _pct(n: int, d: int) -> float:
    return (100.0 * n / d) if d else 0.0

def _quantiles(nums: List[int], q: float) -> float:
    if not nums:
        return 0.0
    s = sorted(nums)
    idx = min(len(s) - 1, max(0, int(math.ceil(q * len(s)) - 1)))
    return float(s[idx])

def _build_batch_payload(repos: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a quantitative summary from repo records that may use either:
    - legacy fields: stats.flagged_count, flags[]
    - new fields: findings[]   ← primary in your schema
    We always prefer 'findings' when present.
    """
    total_repos = len(repos)
    total_files = 0
    total_flagged = 0
    repos_with_findings = 0

    flagged_by_repo: Dict[str, int] = {}
    category_counts = Counter()
    severity_counts = Counter()

    for r in repos:
        name = (
            r.get("repo", {}).get("full_name")
            or (r.get("repo", {}).get("owner") and r.get("repo", {}).get("name") and f"{r['repo']['owner']}/{r['repo']['name']}")
            or r.get("repo", {}).get("html_url")
            or "unknown"
        )
        stats = r.get("stats") or {}
        files_scanned = int(stats.get("files_scanned", 0))
        total_files += files_scanned

        # Prefer findings[] if present
        findings = r.get("findings")
        flags = r.get("flags")  # legacy
        if isinstance(findings, list):
            flagged = len(findings)
            # collect category/severity from findings
            for f in findings:
                cat = (f.get("rule_id") or f.get("scanner") or "Uncategorized")
                sev = (f.get("severity") or "Unspecified")
                category_counts[str(cat).strip()] += 1
                severity_counts[str(sev).strip()] += 1
        elif isinstance(flags, list):
            flagged = len(flags)
            for f in flags:
                cat = (f.get("category") or f.get("rule_id") or "Uncategorized")
                sev = (f.get("severity") or "Unspecified")
                category_counts[str(cat).strip()] += 1
                severity_counts[str(sev).strip()] += 1
        else:
            # fall back to numeric field if neither lists exist
            flagged = int(stats.get("flagged_count", 0))

        total_flagged += flagged
        flagged_by_repo[name] = flagged
        if flagged > 0:
            repos_with_findings += 1

    flagged_values = list(flagged_by_repo.values())
    median_flagged = _quantiles(flagged_values, 0.5)
    p95_flagged = _quantiles(flagged_values, 0.95)

    # Top repos by flagged count
    top_repos = sorted(flagged_by_repo.items(), key=lambda kv: kv[1], reverse=True)[:5]

    batch = {
        "portfolio": {
            "total_repositories": total_repos,
            "total_files_scanned": total_files,
            "total_flagged_files": total_flagged,
            "percent_repos_with_findings": round(_pct(repos_with_findings, total_repos), 2),
            "median_flagged_per_repo": median_flagged,
            "p95_flagged_per_repo": p95_flagged,
        },
        "findings": {
            "by_category": category_counts.most_common(),
            "by_severity": severity_counts.most_common(),
            "top_repositories_by_flagged": top_repos,
        },
        "notes": {
            "assumptions": "Prefer findings[]. If absent, use flags[]; if both absent, use stats.flagged_count or 0.",
            "caveats": "Static analysis only; evidence excerpts are redacted or partial.",
        },
    }
    return batch

def _build_batch_input(batch_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    narr = [
        "Below is BATCH_SUMMARY, a compact quantitative digest covering ALL scanned repositories.",
        "Write a corporate-grade batch report per the instructions.",
        "Use absolute counts and percentages. Be concise and evidence-driven."
    ]
    body = json.dumps(batch_payload, ensure_ascii=False)
    text = "\n".join(narr) + "\n\nBATCH_SUMMARY=\n" + body
    return [{"role": "user", "content": [{"type": "input_text", "text": text}]}]

def write_consolidated_batch_report(
    grouped_repos: List[Dict[str, Any]],
    out_dir: pathlib.Path,
    *,
    model: str,
    temperature: float,
    seed: int,
    max_output_tokens: int,
    session_id: str,
    ts: str,
    render_pdf: bool = False,
    company: str = "MOCOPOS Security",
    logo_path: Optional[str] = None,
) -> pathlib.Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    prefix = stamp_prefix(session_id, ts)
    md_path = out_dir / f"{prefix}.md"

    batch_payload = _build_batch_payload(grouped_repos)
    instructions = render_batch_instructions()
    input_obj = _build_batch_input(batch_payload)

    md = call_openai_responses(
        model=model, instructions=instructions, input_obj=input_obj,
        response_format=None, temperature=temperature, seed=seed,
        max_output_tokens=max_output_tokens,
    )
    md_path.write_text(md, encoding="utf-8")

    if render_pdf:
        pdf_path = md_path.with_suffix(".pdf")
        meta = {
            "title": "Portfolio Security Report",
            "subtitle": "Consolidated Batch Summary",
            "company": company,
            "report_type": "Consolidated",
            "timestamp": ts,
            "session_id": session_id,
            "logo_path": logo_path,
        }
        md_to_pdf(md_path, pdf_path, meta=meta)

    return md_path


# ---------- Public API ----------

def generate_reports_from_path(
    scan_path: pathlib.Path,
    out_dir: pathlib.Path,
    *,
    model: str = "",
    temperature: float = 0.2,
    seed: int = 7,
    max_output_tokens: int = 4096,
    session_id: Optional[str] = None,
    ts: Optional[str] = None,
    render_pdf: bool = False,
    company: str = "MOCOPOS Security",
    logo_path: Optional[str] = None,
) -> List[Tuple[str, pathlib.Path]]:
    items = _load_items(scan_path)
    if not items:
        raise ValueError(f"No records found in {scan_path}")
    grouped = _group_by_repo(items)

    # Derive session/timestamp
    derived = None
    for r in grouped:
        derived = _extract_session_from_repo_obj(r)
        if derived:
            break
    sid = session_id or derived or generate_session_id()
    timestamp = ts or utc_stamp()

    results: List[Tuple[str, pathlib.Path]] = []
    for repo_obj in grouped:
        name, mdp, _pdf = _emit_report(
            repo_obj, out_dir, model, temperature, seed, max_output_tokens,
            session_id=sid, ts=timestamp,
            render_pdf=render_pdf, company=company, logo_path=logo_path
        )
        results.append((name, mdp))
    return results

def generate_consolidated_from_inputs(
    scan_paths: List[pathlib.Path],
    out_dir: pathlib.Path,
    *,
    model: str = "",
    temperature: float = 0.2,
    seed: int = 7,
    max_output_tokens: int = 4096,
    session_id: Optional[str] = None,
    ts: Optional[str] = None,
    render_pdf: bool = False,
    company: str = "MOCOPOS Security",
    logo_path: Optional[str] = None,
) -> pathlib.Path:
    all_items: List[Dict[str, Any]] = []
    for p in scan_paths:
        all_items.extend(_load_items(p))
    grouped = _group_by_repo(all_items)

    # Derive session/timestamp
    derived = None
    for r in grouped:
        derived = _extract_session_from_repo_obj(r)
        if derived:
            break
    sid = session_id or derived or generate_session_id()
    timestamp = ts or utc_stamp()

    return write_consolidated_batch_report(
        grouped, out_dir,
        model=model, temperature=temperature, seed=seed, max_output_tokens=max_output_tokens,
        session_id=sid, ts=timestamp,
        render_pdf=render_pdf, company=company, logo_path=logo_path
    )


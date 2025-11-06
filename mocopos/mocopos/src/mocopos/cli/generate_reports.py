#!/usr/bin/env python3
import argparse
import pathlib
from typing import List, Tuple
from ..reporting.report_generator import (
    generate_reports_from_path,
    write_batch_index,
    generate_consolidated_from_inputs,
)
from ..reporting.session_utils import generate_session_id, utc_stamp

def main():
    p = argparse.ArgumentParser(description="Generate corporate-grade reports (Markdown & optional PDF).")
    p.add_argument("--inputs", nargs="+", required=True)
    p.add_argument("--out-dir", default="reports")
    p.add_argument("--model", default="")
    p.add_argument("--temperature", type=float, default=0.2)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--max-output-tokens", type=int, default=4096)
    p.add_argument("--consolidate", action="store_true",
                   help="Also produce a consolidated BATCH_SUMMARY across ALL inputs.")
    p.add_argument("--only-consolidated", action="store_true",
                   help="Produce ONLY the consolidated batch report (skip per-repo reports).")

    # PDF & branding
    p.add_argument("--pdf", action="store_true", help="Render PDF(s) in addition to Markdown.")
    p.add_argument("--pdf-scope", choices=["consolidated", "per-repo", "both"], default=None,
                   help="Which PDFs to render. If omitted: "
                        "when --only-consolidated → consolidated; else → per-repo.")
    p.add_argument("--company", default="MOCOPOS Security", help="Brand/company name for the PDF header/cover.")
    p.add_argument("--logo", default="", help="Path to a logo image for the cover.")

    p.add_argument("--session-id", default="", help="Optional session id; if omitted a new one is generated.")

    args = p.parse_args()
    out_dir = pathlib.Path(args.out_dir)
    scan_paths = [pathlib.Path(ip) for ip in args.inputs]
    session_id = args.session_id.strip() or generate_session_id()
    ts = utc_stamp()
    logo_path = args.logo if args.logo else None

    # Decide PDF scope
    if args.pdf:
        if args.pdf_scope is None:
            # default behavior: consolidated-only mode → consolidated PDF; otherwise → per-repo PDFs
            pdf_consolidated = args.only_consolidated
            pdf_per_repo = not args.only_consolidated
        else:
            pdf_consolidated = args.pdf_scope in ("consolidated", "both")
            pdf_per_repo = args.pdf_scope in ("per-repo", "both")
    else:
        pdf_consolidated = False
        pdf_per_repo = False

    # CONSOLIDATED-ONLY path
    if args.only_consolidated:
        md_path = generate_consolidated_from_inputs(
            scan_paths, out_dir,
            model=args.model, temperature=args.temperature, seed=args.seed,
            max_output_tokens=args.max_output_tokens,
            session_id=session_id, ts=ts,
            render_pdf=pdf_consolidated, company=args.company, logo_path=logo_path
        )
        print(f"Batch summary written: {md_path}")
        return

    # Default: per-repo reports
    all_results: List[Tuple[str, pathlib.Path]] = []
    for pth in scan_paths:
        paths = list(generate_reports_from_path(
            pth, out_dir,
            model=args.model, temperature=args.temperature, seed=args.seed,
            max_output_tokens=args.max_output_tokens,
            session_id=session_id, ts=ts,
            render_pdf=pdf_per_repo, company=args.company, logo_path=logo_path
        ))
        for repo_name, path in paths:
            print(f"Wrote: {repo_name} → {path}")
        all_results.extend(paths)

    # Optional consolidated too
    if args.consolidate:
        md_path = generate_consolidated_from_inputs(
            scan_paths, out_dir,
            model=args.model, temperature=args.temperature, seed=args.seed,
            max_output_tokens=args.max_output_tokens,
            session_id=session_id, ts=ts,
            render_pdf=pdf_consolidated, company=args.company, logo_path=logo_path
        )
        print(f"Batch summary written: {md_path}")

    # Per-repo index
    if all_results:
        idx = write_batch_index(all_results, out_dir, session_id=session_id, ts=ts)
        print(f"Index: {idx}")

if __name__ == "__main__":
    main()

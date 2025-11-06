from pathlib import Path
from typing import Optional, Dict, Any, List
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, select_autoescape, Template

# NEW: primary renderer (GitHub-flavored)
try:
    from markdown_it import MarkdownIt
    from mdit_py_plugins.table import table_plugin
    from mdit_py_plugins.deflist import deflist_plugin
    from mdit_py_plugins.tasklists import tasklists_plugin
    from mdit_py_plugins.anchors import anchors_plugin
    from mdit_py_plugins.footnote import footnote_plugin
    _MD_ENGINE = "markdown_it"
except Exception:
    _MD_ENGINE = "python_markdown"

# Fallback renderer
try:
    from markdown import markdown as _pm_markdown
except Exception:
    _pm_markdown = None

from weasyprint import HTML, CSS

import re

_THIS_DIR = Path(__file__).resolve().parent
_ASSETS_DIR = _THIS_DIR / "assets"
_TEMPLATES_DIR = _THIS_DIR / "templates"

DEFAULT_CSS = """
:root{ --brand:#0B5FFF; --ink:#111827; --muted:#6B7280; --border:#E5E7EB; --bg:#FFFFFF; --accent:#EEF2FF; }
html,body{ font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans","Apple Color Emoji","Segoe UI Emoji","Segoe UI Symbol";
  color:var(--ink); background:var(--bg); font-size:11pt; line-height:1.55; }
.cover{ display:flex; flex-direction:column; min-height:85vh; padding:8mm 4mm; border-left:6px solid var(--brand);
  background:linear-gradient(180deg,#fff,var(--accent)); }
.cover .logo{ height:40px; margin-bottom:16px; }
.cover h1{ font-size:28pt; margin:0 0 6px 0; color:var(--ink); }
.cover .subtitle{ font-size:12pt; color:var(--muted); margin:0 0 18px 0; }
.cover .meta{ display:grid; grid-template-columns:auto 1fr; gap:6px 12px; font-size:10.5pt; }
.pagebreak{ page-break-after:always; }
.content{ padding:2mm; }
.content h1{ font-size:18pt; margin:14px 0 6px 0; }
.content h2{ font-size:14pt; margin:12px 0 6px 0; }
.content h3{ font-size:12pt; margin:10px 0 6px 0; }
.content p{ margin:6px 0; }
.content pre{ background:#0b5fff10; border:1px solid var(--border); padding:8px; border-radius:6px; overflow-x:auto; }
.content table{ width:100%; border-collapse:collapse; margin:10px 0 14px 0; }
.content th, .content td{ border:1px solid var(--border); padding:6px 8px; text-align:left; vertical-align:top; }
.content th{ background:var(--accent); }
.content table td.num, .content table th.num { text-align:right; white-space:nowrap; }
h1,h2,h3{ page-break-after:avoid; } table, pre, blockquote{ page-break-inside:avoid; }
"""

DEFAULT_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><title>{{ meta.title or "Security Report" }}</title>
<style>
@page{ size:A4; margin:20mm 16mm 22mm 16mm;
  @top-left{ content: "{{ meta.company or 'MOCOPOS Security' }}"; font-size:10pt; color:#6b7280; }
  @top-right{ content: "{{ meta.report_type or 'Report' }}"; font-size:10pt; color:#6b7280; }
  @bottom-left{ content: "{{ meta.timestamp or '' }}  •  {{ meta.session_id or '' }}"; font-size:9pt; color:#9ca3af; }
  @bottom-right{ content: "Page " counter(page) " of " counter(pages); font-size:9pt; color:#9ca3af; } }
</style></head>
<body>
<section class="cover">
  {% if meta.logo_path %}<img class="logo" src="{{ meta.logo_path }}" alt="Logo"/>{% endif %}
  <h1>{{ meta.title or "Security Report" }}</h1>
  <p class="subtitle">{{ meta.subtitle or "Automated Repository Security Analysis" }}</p>
  <div class="meta">
    <div><strong>Company:</strong> {{ meta.company or "MOCOPOS Security" }}</div>
    <div><strong>Report Type:</strong> {{ meta.report_type or "Consolidated" }}</div>
    <div><strong>Timestamp:</strong> {{ meta.timestamp or "" }}</div>
    <div><strong>Session:</strong> {{ meta.session_id or "" }}</div>
  </div>
</section>
<div class="pagebreak"></div>
<main class="content">{{ body_html | safe }}</main>
</body></html>"""

_env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)),
                   autoescape=select_autoescape(["html", "xml"]))


_NUM_WRAP = (
  '<span style="color:#111827 !important;'
  '-webkit-text-fill-color:#111827 !important;'
  'opacity:1 !important;visibility:visible !important;'
  'mix-blend-mode:normal !important;filter:none !important;">\\2</span>'
)

def _force_ink_in_table_numbers(html: str) -> str:
    # Wrap direct text with digits inside <td> / <th> so color cannot be overridden.
    html = re.sub(r'(<td\b[^>]*>)([^<]*\d[^<]*)(</td>)',
                  r'\1' + _NUM_WRAP + r'\3', html, flags=re.IGNORECASE)
    html = re.sub(r'(<th\b[^>]*>)([^<]*\d[^<]*)(</th>)',
                  r'\1' + _NUM_WRAP + r'\3', html, flags=re.IGNORECASE)
    return html

def _normalize_tables(md_text: str) -> str:
    """
    Safety net so table blocks render as real <table>:
    - Only touch lines that *look* like table rows (start with '|')
    - Skip fenced code blocks (``` or ~~~)
    - Ensure a blank line before and after each contiguous table block
    - Remove leading indentation on table lines
    """
    lines = md_text.splitlines()
    out = []
    i = 0
    in_code = False
    fence = None  # "```" or "~~~"

    def is_fence(line: str) -> bool:
        s = line.lstrip()
        return s.startswith("```") or s.startswith("~~~")

    while i < len(lines):
        line = lines[i]

        # Toggle code-fence state
        if is_fence(line):
            tok = line.lstrip()[:3]
            if not in_code:
                in_code, fence = True, tok
            else:
                # only close if matching the same fence token
                if line.lstrip().startswith(fence):
                    in_code, fence = False, None
            out.append(line)
            i += 1
            continue

        # Do not touch anything inside fenced code
        if in_code:
            out.append(line)
            i += 1
            continue

        # Potential table block (GFM)
        if line.lstrip().startswith('|'):
            # Insert a blank line before, if needed
            if out and out[-1].strip() != '':
                out.append('')
            # Consume contiguous table-ish lines
            while i < len(lines) and lines[i].lstrip().startswith('|'):
                out.append(lines[i].lstrip())
                i += 1
            # Blank line after table block
            out.append('')
            continue

        out.append(line)
        i += 1

    return "\n".join(out)


def _md_to_html_body(md_text: str) -> str:
    """
    Convert Markdown to HTML, robustly:
    - Guard against None / "None"
    - Prefer markdown-it-py (GFM tables, etc.); fall back to python-markdown if available
    - Optionally normalize tables if a `_normalize_tables` helper exists in this module
    """
    # 0) Guard against None / "None"
    if not md_text or str(md_text).strip().lower() == "none":
        return "<p><em>No content to render.</em></p>"

    # 1) Optional normalization step (safe no-op if absent)
    normalizer = globals().get("_normalize_tables")
    if callable(normalizer):
        try:
            md_text = normalizer(md_text)
        except Exception:
            # normalization is best-effort; don't fail rendering
            pass

    # 2) Primary renderer: markdown-it-py with common GFM plugins
    try:
        from markdown_it import MarkdownIt
        from mdit_py_plugins.table import table_plugin
        from mdit_py_plugins.deflist import deflist_plugin
        from mdit_py_plugins.tasklists import tasklists_plugin
        from mdit_py_plugins.footnote import footnote_plugin
        from mdit_py_plugins.anchors import anchors_plugin

        md = (
            MarkdownIt("gfm-like", {"typographer": False})
            .use(table_plugin)
            .use(deflist_plugin)
            .use(tasklists_plugin, enabled=True)
            .use(footnote_plugin)
            .use(anchors_plugin, max_level=4)
        )
        return md.render(md_text)
    except Exception:
        pass  # fall back

    # 3) Fallback renderer: python-markdown (if installed)
    try:
        from markdown import markdown as _pm_markdown
        return _pm_markdown(
            md_text,
            extensions=["extra", "tables", "fenced_code", "admonition", "toc"],
        )
    except Exception:
        # 4) Last-resort: return escaped-ish placeholder so WeasyPrint shows something
        return "<p><em>Unable to render Markdown; required renderers not available.</em></p>"

def _render_html(md_text: str, meta: Dict[str, Any]) -> str:
    body_html = _md_to_html_body(md_text)
    if meta.get("logo_path"):
        meta["logo_path"] = str(Path(meta["logo_path"]).resolve())
    try:
        template = _env.get_template("report.html")
        return template.render(body_html=body_html, meta=meta)
    except TemplateNotFound:
        return Template(DEFAULT_TEMPLATE).render(body_html=body_html, meta=meta)

def md_to_pdf(md_path: Path, pdf_path: Path, *, meta: Optional[Dict[str, Any]] = None):
    """
    Read Markdown from `md_path`, render to HTML, and write a PDF to `pdf_path`.
    - Defensively handles None/"None"/empty content with a clear placeholder
    - Writes a sidecar HTML next to the PDF for debugging
    - Uses project CSS if present; falls back to DEFAULT_CSS otherwise
    """
    meta = meta or {}

    # 1) Read Markdown; guard against empty/"None"
    try:
        md_text = Path(md_path).read_text(encoding="utf-8")
    except Exception as e:
        md_text = f"# Report generation failed\n\n_Could not read source markdown: {e}_"

    if not md_text or md_text.strip().lower() == "none":
        md_text = "# Report generation failed\n\n_No content was produced by the upstream step._"

    # 2) Render HTML via template pipeline
    html = _render_html(md_text, meta)

    # 3) (Optional) post-process: force visible numerals inside table cells
    #    If you added `_force_ink_in_table_numbers`, we call it here (safe no-op if absent)
    post = globals().get("_force_ink_in_table_numbers")
    if callable(post):
        try:
            html = post(html)
        except Exception:
            pass

    # 4) Emit sidecar HTML for inspection
    try:
        debug_html = pdf_path.with_suffix(".html")
        debug_html.write_text(html, encoding="utf-8")
    except Exception:
        pass  # don't fail PDF creation if we can't write the debug file

    # 5) Prepare output dir
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    # 6) Apply CSS (project CSS if present; else DEFAULT_CSS fallback)
    stylesheets = []
    base_url = str(_ASSETS_DIR) if (_ASSETS_DIR.exists()) else str(_THIS_DIR)
    try:
        css_file = _ASSETS_DIR / "report.css"
        if css_file.exists():
            stylesheets.append(CSS(filename=str(css_file)))
        else:
            # fallback to built-in CSS string
            stylesheets.append(CSS(string=DEFAULT_CSS))
    except Exception:
        # if CSS loading fails, still try to render the PDF with no stylesheet
        pass

    # 7) Render PDF
    HTML(string=html, base_url=base_url).write_pdf(target=str(pdf_path), stylesheets=stylesheets)
    return pdf_path

from __future__ import annotations
import html, json, re
from collections import defaultdict
from importlib import resources
from typing import Dict, List

# ---- Fallback HTML/CSS (no Jinja) ----
_FALLBACK_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AppPolicy Report</title>
  <style>{{ CSS }}</style>
</head>
<body>
  <header>
    <h1>AppPolicy Report</h1>
    <div class="summary">
      <span class="badge sev-blocking">Blocking: {{ BLOCKING_COUNT }}</span>
      <span class="badge sev-advisory">Advisory: {{ ADVISORY_COUNT }}</span>
      <span class="badge sev-fyi">FYI: {{ FYI_COUNT }}</span>
    </div>
  </header>
  <main>
    <section><h2>iOS</h2><div class="cards">{{ IOS_CARDS }}</div></section>
    <section><h2>Android</h2><div class="cards">{{ ANDROID_CARDS }}</div></section>
    <section><h2>Other</h2><div class="cards">{{ OTHER_CARDS }}</div></section>
  </main>
</body>
</html>
"""

_FALLBACK_CSS = """:root { --bg:#fff; --fg:#111; --muted:#666; --card:#fafafa; }
body { font-family: system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; background:var(--bg); color:var(--fg); margin:24px; }
.summary { margin: 6px 0 18px; }
.badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:12px; margin-right:6px; }
.sev-blocking { background:#fee; color:#900; } .sev-advisory { background:#eef; color:#225; } .sev-fyi { background:#efe; color:#252; }
.cards { display:grid; gap:12px; grid-template-columns:1fr; }
.card { background:var(--card); border:1px solid #e5e5e5; border-radius:12px; padding:14px; }
.title { font-weight:600; margin-bottom:6px; }
.policy { margin:4px 0 8px; color:var(--muted); }
"""

def _res_text(path: str) -> str:
    """Load a resource inside the apcop package or return ''."""
    try:
        return (resources.files("apcop") / path).read_text(encoding="utf-8")
    except Exception:
        return ""

def severity_badge(sev: str) -> str:
    sev = (sev or "advisory").lower()
    cls = {"blocking":"sev-blocking","advisory":"sev-advisory","fyi":"sev-fyi"}.get(sev,"sev-advisory")
    return f'<span class="badge {cls}">{html.escape(sev.upper())}</span>'

def _render_card(f: Dict) -> str:
    sev = f.get("severity","advisory")
    because = f.get("because",{}) or {}
    url = because.get("url") or ""; section = because.get("section") or ""
    plat = (f.get("platform") or "").lower()
    plat_badge = " 🍎 iOS" if plat=="ios" else (" 🤖 Android" if plat=="android" else "")

    doc_link = ""
    if url or section:
        link_text = html.escape(section) if section else html.escape(url)
        doc_link = f'<div class="policy"><b>Policy:</b> <a href="{html.escape(url) or "#"}" target="_blank" rel="noreferrer noopener">{link_text}</a></div>'

    # Why/How from rule metadata
    section_text = because.get("section") or ""
    remediation = []
    then_obj = f.get("then") or {}
    if isinstance(then_obj, dict) and isinstance(then_obj.get("remediation"), list):
        remediation = then_obj["remediation"]
    if not remediation:
        remediation = f.get("remediation") or []
    why_html = f'<div class="why"><b>Why this matters:</b> {html.escape(section_text)}</div>' if section_text else ""
    how_html = ""
    if remediation:
        items = "".join(f"<li>{html.escape(r)}</li>" for r in remediation)
        how_html = f'<div class="how"><b>How to fix:</b><ul>{items}</ul></div>'

    evidence = f.get("evidence") or {}
    ev_html = f"<details><summary>Evidence</summary><pre>{html.escape(json.dumps(evidence, indent=2))}</pre></details>" if evidence else ""

    return (
        '<div class="card">'
        f'<div class="title">{severity_badge(sev)} <span class="id">{html.escape(f.get("id",""))}</span>{plat_badge}</div>'
        f'{doc_link}{why_html}{how_html}{ev_html}'
        '</div>'
    )

def render_html(report: Dict) -> str:
    # Load packaged Jinja template (if any), else fall back
    template = _res_text("templates/report.html")
    css = _res_text("assets/report.css") or _FALLBACK_CSS

    # Build groups and counts
    grouped = defaultdict(list)
    for f in report.get("findings",[]) or []:
        grouped[(f.get("platform") or "other").lower()].append(f)

    def cards_html(key: str) -> str:
        L = grouped.get(key, [])
        return "\n".join(_render_card(f) for f in L) if L else '<div class="card">No findings.</div>'

    summary = report.get("summary") or {}
    ctx_counts = {
        "blocking": int(summary.get("blocking",0) or 0),
        "advisory": int(summary.get("advisory",0) or 0),
        "fyi":      int(summary.get("fyi",0) or 0),
    }

    # If template looks like Jinja, render with jinja2; else use token replacement
    if template and re.search(r"({{.*?}}|{%.+?%})", template, re.S):
        try:
            from jinja2 import Environment, BaseLoader, select_autoescape
            env = Environment(
                loader=BaseLoader(),
                autoescape=select_autoescape(enabled_extensions=("html",)),
                undefined=None,
                trim_blocks=True,
                lstrip_blocks=True,
            )
            jtpl = env.from_string(template)
            groups = [
                {"name":"iOS", "key":"ios",     "cards": cards_html("ios")},
                {"name":"Android","key":"android","cards": cards_html("android")},
                {"name":"Other", "key":"other", "cards": cards_html("other")},
            ]
            return jtpl.render(
                css=css,
                summary=ctx_counts,
                groups=groups,
            )
        except Exception:
            # If Jinja not installed or template errors, fall through to fallback
            pass

    # Plain replacement path (fallback template)
    base = template or _FALLBACK_TEMPLATE
    return (base
            .replace("{{ CSS }}", css)
            .replace("{{ BLOCKING_COUNT }}", str(ctx_counts["blocking"]))
            .replace("{{ ADVISORY_COUNT }}", str(ctx_counts["advisory"]))
            .replace("{{ FYI_COUNT }}", str(ctx_counts["fyi"]))
            .replace("{{ IOS_CARDS }}", cards_html("ios"))
            .replace("{{ ANDROID_CARDS }}", cards_html("android"))
            .replace("{{ OTHER_CARDS }}", cards_html("other")))

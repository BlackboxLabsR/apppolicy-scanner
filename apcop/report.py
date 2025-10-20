from __future__ import annotations
import html, json, re
from collections import defaultdict
from importlib import resources
from typing import Dict, List

# Fallback HTML/CSS (no Jinja) that includes summary counts and rendered cards
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

    # policy link
    doc_link = ""
    if url or section:
        link_text = html.escape(section) if section else html.escape(url)
        doc_link = f'<div class="policy"><b>Policy:</b> <a href="{html.escape(url) or "#"}" target="_blank" rel="noreferrer noopener">{link_text}</a></div>'

    # why/how
    section_text = because.get("section") or ""
    remediation: List[str] = []
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

    # evidence
    ev = f.get("evidence") or {}
    ev_html = f"<details><summary>Evidence</summary><pre>{html.escape(json.dumps(ev, indent=2))}</pre></details>" if ev else ""

    return (
        '<div class="card">'
        f'<div class="title">{severity_badge(sev)} <span class="id">{html.escape(f.get("id",""))}</span>{plat_badge}</div>'
        f'{doc_link}{why_html}{how_html}{ev_html}'
        '</div>'
    )

def _cards_for(grouped: Dict[str, List[Dict]], key: str) -> str:
    L = grouped.get(key, [])
    return "\n".join(_render_card(f) for f in L) if L else '<div class="card">No findings.</div>'

def render_html(report: Dict) -> str:
    # Load packaged template (may be Jinja) and CSS
    jinja_template = _res_text("templates/report.html")
    css = _res_text("assets/report.css") or _FALLBACK_CSS

    # group findings and counts
    grouped: Dict[str, List[Dict]] = defaultdict(list)
    for f in report.get("findings", []) or []:
        grouped[(f.get("platform") or "other").lower()].append(f)
    summary = report.get("summary") or {}
    counts = {
        "blocking": int(summary.get("blocking", 0) or 0),
        "advisory": int(summary.get("advisory", 0) or 0),
        "fyi":      int(summary.get("fyi", 0) or 0),
    }

    # If the template looks like Jinja, try to render with Jinja2.
    if jinja_template and re.search(r"({{.*?}}|{%.+?%})", jinja_template, re.S):
        try:
            from jinja2 import Environment, BaseLoader, select_autoescape
            env = Environment(loader=BaseLoader(),
                              autoescape=select_autoescape(enabled_extensions=("html",)),
                              trim_blocks=True, lstrip_blocks=True)
            jtpl = env.from_string(jinja_template)
            groups_ctx = [
                {"name": "iOS",     "cards": _cards_for(grouped, "ios")},
                {"name": "Android", "cards": _cards_for(grouped, "android")},
                {"name": "Other",   "cards": _cards_for(grouped, "other")},
            ]
            return jtpl.render(css=css, summary=counts, groups=groups_ctx)
        except Exception:
            # No Jinja or template error — fall back to pure HTML template below
            pass

    # Fall back to simple string-replacement template that always shows counts/cards
    base = _FALLBACK_TEMPLATE
    return (base
            .replace("{{ CSS }}", css)
            .replace("{{ BLOCKING_COUNT }}", str(counts["blocking"]))
            .replace("{{ ADVISORY_COUNT }}", str(counts["advisory"]))
            .replace("{{ FYI_COUNT }}", str(counts["fyi"]))
            .replace("{{ IOS_CARDS }}", _cards_for(grouped, "ios"))
            .replace("{{ ANDROID_CARDS }}", _cards_for(grouped, "android"))
            .replace("{{ OTHER_CARDS }}", _cards_for(grouped, "other")))

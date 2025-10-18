from __future__ import annotations
import html
from collections import defaultdict
from importlib import resources
from typing import Dict, List

# NOTE: We keep rendering logic here but structure & CSS live in /templates and /assets.

def _load_text(package: str, resource_path: str) -> str:
    """
    Load a text resource from the package (PEP 302 importlib.resources).
    """
    return resources.files(package).joinpath(resource_path).read_text(encoding="utf-8")

def severity_badge(sev: str) -> str:
    sev = (sev or "advisory").lower()
    cls = {"blocking": "sev-blocking", "advisory": "sev-advisory", "fyi": "sev-fyi"}.get(sev, "sev-advisory")
    return f'<span class="badge {cls}">{html.escape(sev.upper())}</span>'

def _render_card(f: Dict) -> str:
    sev = f.get("severity", "advisory")
    because = f.get("because", {}) or {}
    url = because.get("url") or ""
    section = because.get("section") or ""
    doc_link = ""
    if url or section:
        link_text = html.escape(section) if section else html.escape(url)
        u = html.escape(url) if url else "#"
        doc_link = f'<div class="policy"><b>Policy:</b> <a href="{u}" target="_blank" rel="noreferrer noopener">{link_text}</a></div>'

    # Placeholders for now (later can be enriched from rule metadata)
    why = f.get("why") or f"Rule **{html.escape(f.get('id',''))}** triggered by detected facts."
    how = f.get("how") or "See linked policy for remediation steps; update settings/permissions/metadata accordingly."

    # Evidence (optional)
    evidence = f.get("evidence") or {}
    ev_html = ""
    if evidence:
        import json
        ev_html = f"<details><summary>Evidence</summary><pre>{html.escape(json.dumps(evidence, indent=2))}</pre></details>"

    return (
        '<div class="card">'
        f'<div class="title">{severity_badge(sev)} <span class="id">{html.escape(f.get("id",""))}</span></div>'
        f'{doc_link}'
        f'<div class="why"><b>Why this matters:</b> {html.escape(why)}</div>'
        f'<div class="how"><b>How to fix:</b> {html.escape(how)}</div>'
        f'{ev_html}'
        '</div>'
    )

def render_html(report: Dict) -> str:
    # Load template & CSS from package resources
    template = _load_text("apcop.templates", "report.html")
    css = _load_text("apcop.assets", "report.css")

    # Group findings by platform
    grouped: Dict[str, List[Dict]] = defaultdict(list)
    for f in report.get("findings", []) or []:
        grouped[(f.get("platform") or "other").lower()].append(f)

    def render_group(key: str) -> str:
        return "\n".join(_render_card(f) for f in grouped.get(key, [])) or "<div class=\"card\">No findings.</div>"

    summary = report.get("summary") or {}
    blocking = int(summary.get("blocking", 0) or 0)
    advisory = int(summary.get("advisory", 0) or 0)
    fyi = int(summary.get("fyi", 0) or 0)

    html_out = (
        template
        .replace("{{ CSS }}", css)
        .replace("{{ BLOCKING_COUNT }}", str(blocking))
        .replace("{{ ADVISORY_COUNT }}", str(advisory))
        .replace("{{ FYI_COUNT }}", str(fyi))
        .replace("{{ IOS_CARDS }}", render_group("ios"))
        .replace("{{ ANDROID_CARDS }}", render_group("android"))
        .replace("{{ OTHER_CARDS }}", render_group("other"))
    )
    return html_out

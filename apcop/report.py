from __future__ import annotations
import html
import json
from collections import defaultdict
from importlib import resources
from typing import Dict, List

def _load_text(package: str, resource_path: str) -> str:
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

    plat = (f.get("platform") or "").lower()
    plat_badge = " 🍎 iOS" if plat == "ios" else (" 🤖 Android" if plat == "android" else "")
    title = f'<div class="title">{severity_badge(sev)} <span class="id">{html.escape(f.get("id",""))}</span>{plat_badge}</div>'

    doc_link = ""
    if url or section:
        link_text = html.escape(section) if section else html.escape(url)
        u = html.escape(url) if url else "#"
        doc_link = f'<div class="policy"><b>Policy:</b> <a href="{u}" target="_blank" rel="noreferrer noopener">{link_text}</a></div>'

    # Why / How from rule metadata
    section_text = because.get("section") or ""
    remediation = []
    then_obj = f.get("then") or {}
    if isinstance(then_obj, dict):
        rem = then_obj.get("remediation")
        if isinstance(rem, list):
            remediation = rem
    if not remediation:
        remediation = f.get("remediation") or []

    why_html = f'<div class="why"><b>Why this matters:</b> {html.escape(section_text)}</div>' if section_text else ""
    how_html = ""
    if remediation:
        items = "".join(f"<li>{html.escape(r)}</li>" for r in remediation)
        how_html = f'<div class="how"><b>How to fix:</b><ul>{items}</ul></div>'

    # Evidence
    evidence = f.get("evidence") or {}
    ev_html = ""
    if evidence:
        ev_html = f"<details><summary>Evidence</summary><pre>{html.escape(json.dumps(evidence, indent=2))}</pre></details>"

    return (
        '<div class="card">'
        f'{title}{doc_link}{why_html}{how_html}{ev_html}'
        '</div>'
    )

def render_html(report: Dict) -> str:
    template = _load_text("apcop.templates", "report.html")
    css = _load_text("apcop.assets", "report.css")

    grouped: Dict[str, List[Dict]] = defaultdict(list)
    for f in report.get("findings", []) or []:
        grouped[(f.get("platform") or "other").lower()].append(f)

    def render_group(key: str) -> str:
        cards = [_render_card(f) for f in grouped.get(key, [])]
        return "\n".join(cards) if cards else '<div class="card">No findings.</div>'

    summary = report.get("summary") or {}
    blocking = int(summary.get("blocking", 0) or 0)
    advisory = int(summary.get("advisory", 0) or 0)
    fyi = int(summary.get("fyi", 0) or 0)

    return (template
            .replace("{{ CSS }}", css)
            .replace("{{ BLOCKING_COUNT }}", str(blocking))
            .replace("{{ ADVISORY_COUNT }}", str(advisory))
            .replace("{{ FYI_COUNT }}", str(fyi))
            .replace("{{ IOS_CARDS }}", render_group("ios"))
            .replace("{{ ANDROID_CARDS }}", render_group("android"))
            .replace("{{ OTHER_CARDS }}", render_group("other")))

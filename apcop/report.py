from __future__ import annotations
import html
import json
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

# --- Curated Why/How for top rules (fallbacks applied if not present) ----
WHY_MAP: Dict[str, str] = {
    "android.target_sdk.minimum":
        "Google Play requires apps to target recent Android API levels to ensure security and platform compatibility.",
    "android.permission.background_location.disclosure":
        "Background location access is sensitive; Play policy requires limited use and clear disclosure.",
    "apple.required_reason.pasteboard":
        "UIPasteboard access can expose user data; Apple requires a declared reason in the Privacy Manifest.",
    "apple.account_deletion.required":
        "If users can create an account, they must be able to delete it within the app (App Store Guideline 5.1.1(v)).",
}

HOW_MAP: Dict[str, List[str]] = {
    "android.target_sdk.minimum": [
        "Update `targetSdkVersion` in `build.gradle` to the current policy minimum.",
        "Run a regression build and address any API behavior changes.",
        "Re-submit after confirming store requirements are met."
    ],
    "android.permission.background_location.disclosure": [
        "Provide prominent in-app disclosure describing the background usage.",
        "Limit access to cases where it is strictly necessary; prefer foreground location when possible.",
        "Ensure store listing reflects location usage per Play policy."
    ],
    "apple.required_reason.pasteboard": [
        "Add a UIPasteboard reason to `PrivacyInfo.xcprivacy` (Privacy Manifest).",
        "Remove or gate unnecessary pasteboard reads; prefer explicit user actions where possible."
    ],
    "apple.account_deletion.required": [
        "Add an in-app 'Delete Account' path reachable wherever accounts can be created.",
        "Invoke backend deletion and remove associated data as applicable.",
        "Confirm behavior with Apple’s guideline 5.1.1(v) before re-submit."
    ],
}

def _why_how_for(f: Dict) -> tuple[str, List[str]]:
    """Return (why, how_list) with graceful fallbacks using the rule's 'because' fields."""
    fid = f.get("id", "")
    because = f.get("because", {}) or {}
    url = (because.get("url") or "").strip()
    section = (because.get("section") or "").strip()

    why = WHY_MAP.get(fid)
    how = HOW_MAP.get(fid)

    if not why:
        base = "This may impact review/approval or violate current policy."
        if section:
            base = f"{section}. " + base
        why = base

    if not how:
        tip = "See the linked policy documentation for exact remediation steps."
        if url:
            tip = f"Review the policy doc and update your app accordingly: {url}"
        how = [tip]

    return why, how

def _render_card(f: Dict) -> str:
    sev = f.get("severity", "advisory")
    because = f.get("because", {}) or {}
    url = because.get("url") or ""
    section = because.get("section") or ""
    doc_link = ""
    if url or section:
        link_text = html.escape(section) if section else html.escape(url)
        u = html.escape(url) if url else "#"
        # fixed anchor tag
        doc_link = f'<div class="policy"><b>Policy:</b> <a href="{u}" target="_blank" rel="noreferrer noopener">{link_text}</a></div>'

    # Why / How (curated + fallbacks)
    why, how_list = _why_how_for(f)

    # Missing / Required list (if any)
    missing = f.get("missing") or []
    missing_html = ""
    if missing:
        items = []
        for m in missing:
            if isinstance(m, dict):
                items.append(f"<li><code>{html.escape(json.dumps(m))}</code></li>")
            else:
                items.append(f"<li><code>{html.escape(str(m))}</code></li>")
        missing_html = "<div><strong>Missing / Required:</strong></div><ul>" + "".join(items) + "</ul>"

    # Evidence (optional)
    evidence = f.get("evidence") or {}
    ev_html = ""
    if evidence:
        ev_html = f"<details><summary>Evidence</summary><pre>{html.escape(json.dumps(evidence, indent=2))}</pre></details>"

    # Render How list as bullets
    how_html = ""
    if how_list:
        bullets = "".join(f"<li>{html.escape(step)}</li>" for step in how_list)
        how_html = f'<div class="how"><b>How to fix:</b><ul>{bullets}</ul></div>'

    return (
        '<div class="card">'
        f'<div class="title">{severity_badge(sev)} <span class="id">{html.escape(f.get("id",""))}</span></div>'
        f'{doc_link}'
        f'<div class="why"><b>Why this matters:</b> {html.escape(why)}</div>'
        f'{how_html}'
        f'{missing_html}'
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
        cards = [_render_card(f) for f in grouped.get(key, [])]
        return "\n".join(cards) if cards else '<div class="card">No findings.</div>'

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

import html, json
CSS = '''
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 24px; }
.badge { display:inline-block; padding:2px 8px; border-radius:8px; font-size:12px; }
.sev-blocking { background:#fee; color:#900; }
.sev-advisory { background:#eef; color:#225; }
.sev-fyi { background:#efe; color:#252; }
.card { border:1px solid #ddd; border-radius:8px; padding:16px; margin:16px 0; }
h1 { margin-top:0; }
code { background:#f5f5f5; padding:1px 4px; border-radius:4px; }
a { color:#06c; text-decoration:none; }
a:hover { text-decoration:underline; }
'''
def severity_badge(sev):
    cls = {"blocking":"sev-blocking","advisory":"sev-advisory","fyi":"sev-fyi"}.get(sev, "sev-advisory")
    return f'<span class="badge {cls}">{html.escape(sev.upper())}</span>'
def render_html(report: dict) -> str:
    parts = []
    parts.append("<!doctype html><meta charset='utf-8'><title>AppPolicy Report</title>")
    parts.append(f"<style>{CSS}</style>")
    parts.append("<h1>AppPolicy Copilot — Report</h1>")
    summary = report.get("summary", {})
    parts.append(f"<p>Summary: Blocking {summary.get('blocking',0)} • Advisory {summary.get('advisory',0)} • FYI {summary.get('fyi',0)}</p>")
    for f in report.get("findings", []):
        sev = f.get("severity","advisory")
        because = f.get("because",{})
        url = because.get("url","")
        section = because.get("section","")
        parts.append('<div class="card">')
        parts.append(f"<div>{severity_badge(sev)} <strong>{html.escape(f.get('id',''))}</strong></div>")
        link = f" — <a href='{html.escape(url)}' target='_blank'>{html.escape(section or url)}</a>" if (section or url) else ""
        parts.append(f"<div style='margin:6px 0 12px 0;'>Policy{link}</div>")
        missing = f.get("missing",[])
        if missing:
            parts.append("<div><strong>Missing / Required:</strong></div><ul>")
            for m in missing:
                parts.append(f"<li><code>{html.escape(json.dumps(m) if isinstance(m,dict) else str(m))}</code></li>")
            parts.append("</ul>")
        ev = f.get("evidence", {})
        if ev:
            parts.append("<details><summary>Evidence</summary><pre>")
            parts.append(html.escape(json.dumps(ev, indent=2)))
            parts.append("</pre></details>")
        parts.append("</div>")
    return "\n".join(parts)

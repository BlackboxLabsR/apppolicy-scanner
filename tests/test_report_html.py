from apcop.report import render_html
import re, os

def test_render_html_groups_and_summary(tmp_path):
    report = {
        "summary": {"blocking": 1, "advisory": 1, "fyi": 0},
        "findings": [
            {
                "id": "android.target_sdk.minimum",
                "platform": "android",
                "severity": "blocking",
                "because": {
                    "url": "https://developer.android.com/google/play/requirements/target-sdk",
                    "section": "Target API level"
                },
                "evidence": {"policy_minimum": 34, "facts_used": {"android.targetsdk": 31}},
                "status": "fail"
            },
            {
                "id": "apple.permissions.camera.usage_description",
                "platform": "ios",
                "severity": "advisory",
                "because": {
                    "url": "https://developer.apple.com/documentation/bundleresources/information_property_list/nscamerausagedescription",
                    "section": "Camera — Usage Description"
                },
                "status": "warn"
            }
        ]
    }

    html_text = render_html(report)

    # Save for debugging
    tmp_file = tmp_path / "report.html"
    tmp_file.write_text(html_text, encoding="utf-8")
    with open(os.path.abspath("report_debug.html"), "w", encoding="utf-8") as f:
        f.write(html_text)

    # Title present
    assert "AppPolicy Copilot — Report" in html_text

    # Match actual summary line (no colons after Blocking/Advisory)
    assert re.search(
        r"Summary:\s*Blocking\s*:?\s*1\W+Advisory\s*:?\s*1\W+FYI\s*:?\s*0",
        html_text,
        re.I | re.S,
)
    # Findings present (IDs and policy section text)
    assert "android.target_sdk.minimum" in html_text
    assert "apple.permissions.camera.usage_description" in html_text
    assert "Target API level" in html_text

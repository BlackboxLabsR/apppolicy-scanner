from apcop.report import render_html
import re

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
    (tmp_path / "report.html").write_text(html_text, encoding="utf-8")

    # Basic title check
    assert "AppPolicy Copilot — Report" in html_text

    # Summary numbers (flexible formatting)
    assert re.search(r"Blocking\D*1", html_text, re.I)
    assert re.search(r"Advisory\D*1", html_text, re.I)
    assert re.search(r"FYI\D*0", html_text, re.I)

    # Findings present
    assert "android.target_sdk.minimum" in html_text
    assert "apple.permissions.camera.usage_description" in html_text
    assert "Target API level" in html_text

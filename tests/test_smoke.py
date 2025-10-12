from apcop.rules import evaluate_rules, load_rules
def test_smoke():
    facts = [
        {"platform":"android","permissions":["android.permission.ACCESS_BACKGROUND_LOCATION"],"targetsdk":31},
        {"platform":"ios","plist_keys":["NSCameraUsageDescription"],"signals":{"symbols":["UIImagePickerController"]}}
    ]
    rules = load_rules("rules/community.yaml")
    report = evaluate_rules(facts, rules)
    assert "findings" in report and isinstance(report["findings"], list)

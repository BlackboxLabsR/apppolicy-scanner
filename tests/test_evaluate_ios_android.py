from apcop.rules import evaluate_rules

def test_android_target_sdk_blocker():
    facts = [{"platform": "android", "permissions": [], "targetsdk": 31}]
    rules = {
      "version": "t",
      "rules": [{
        "id": "android.target_sdk.minimum",
        "platform":"android", "severity":"blocking",
        "when": {"all": [{"android.targetsdk.lt_policy_min": 34}]},
        "then": {"policy_min": 34, "require": []},
        "because": {}
      }]
    }
    report = evaluate_rules(facts, rules)
    assert any(f["id"]=="android.target_sdk.minimum" and f["severity"]=="blocking" for f in report["findings"])

def test_ios_required_reason_pasteboard_advisory_to_blocking_template():
    facts = [{"platform":"ios",
              "plist_keys":[], "entitlements":{},
              "privacy_manifest":{},
              "signals":{"sdk_names":[], "symbols":["UIPasteboard"], "auth_present":False}}]
    rules = {
      "version": "t",
      "rules": [{
        "id":"apple.required_reason.pasteboard",
        "platform":"ios","severity":"blocking",
        "when":{"any":[{"ios.api.uses":"UIPasteboard"}]},
        "then":{"require":[{"ios.privacy.reason":"pasteboard"}]},
        "because":{"url":"https://developer.apple.com/documentation/bundleresources/privacy_manifest_files"}
      }]
    }
    r = evaluate_rules(facts, rules)
    assert any(f["id"]=="apple.required_reason.pasteboard" and f["severity"]=="blocking" for f in r["findings"])

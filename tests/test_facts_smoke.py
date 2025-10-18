def test_android_targetsdk_fixture():
    from apcop.rules import evaluate_rules
    rules = {"version":"t","rules":[
      {"id":"android.target_sdk.minimum","platform":"android","severity":"blocking",
       "when":{"all":[{"android.targetsdk.lt_policy_min":34}]},
       "then":{"policy_min":34,"require":[]}, "because":{"url":"u"}}
    ]}
    facts = [{"platform":"android","permissions":[],"targetsdk":31}]
    report = evaluate_rules(facts, rules)
    assert any(f["id"]=="android.target_sdk.minimum" and f["severity"]=="blocking" for f in report["findings"])

import yaml, json

def load_rules(path):
    return yaml.safe_load(open(path, "r", encoding="utf-8"))

def index_facts(facts_list):
    idx = {}
    for f in facts_list:
        plat = f.get("platform")
        if plat == "ios":
            idx["ios.plist_keys"] = set(f.get("plist_keys", []))
            idx["ios.entitlements"] = f.get("entitlements", {})
            idx["ios.privacy_manifest"] = f.get("privacy_manifest", {})
            idx["ios.sdk_names"] = set(f.get("signals", {}).get("sdk_names", []))
            idx["ios.symbols"] = set(f.get("signals", {}).get("symbols", []))
            idx["ios.auth_present"] = bool(f.get("signals", {}).get("auth_present", False))
        elif plat == "android":
            idx["android.permissions"] = set(f.get("permissions", []))
            idx["android.targetsdk"] = f.get("targetsdk")
            idx["android.deps"] = set(f.get("deps", []))
    return idx

def has_privacy_manifest_reason(idx, reason_keyword: str):
    d = idx.get("ios.privacy_manifest") or {}
    s = json.dumps(d).lower()
    return reason_keyword.lower() in s

def match_condition(cond, idx):
    if "any" in cond:
        return any(match_condition(c, idx) for c in cond["any"])
    if "all" in cond:
        return all(match_condition(c, idx) for c in cond["all"])

    if len(cond.keys()) != 1:
        return False
    key, value = next(iter(cond.items()))

    if key == "ios.api.uses":
        return value in idx.get("ios.symbols", set())
    if key == "ios.sdk.present":
        v = str(value).lower()
        if v == "any_ads_or_clipboard_sdk":
            names = ",".join(idx.get("ios.sdk_names", set())).lower()
            hints = ["adsupport","googlemobileads","appsflyer","adjust","applovin","ironsource","unityads","tiktok"]
            return any(h in names for h in hints)
        return value in idx.get("ios.sdk_names", set())
    if key == "ios.signin.present":
        return bool(idx.get("ios.auth_present", False))
    if key == "ios.plist.has":
        return value in idx.get("ios.plist_keys", set())
    if key == "ios.privacy.reason":
        return has_privacy_manifest_reason(idx, str(value))

    if key == "android.permission.present":
        return value in idx.get("android.permissions", set())
    if key == "android.targetsdk.lt_policy_min":
        tsdk = idx.get("android.targetsdk")
        try:
            return tsdk is not None and int(tsdk) < int(value)
        except Exception:
            return False

    if key == "exists.true":
        return bool(idx.get(value, False))

    return False

def evaluate_rules(facts_list, rules_doc):
    idx = index_facts(facts_list)
    version = rules_doc.get("version", "0")
    rules = rules_doc.get("rules", [])
    findings = []

    for r in rules:
        rid = r.get("id")
        severity = r.get("severity", "advisory")
        platform = r.get("platform")
        because = r.get("because", {})
        require = (r.get("then") or {}).get("require", [])
        policy_min = (r.get("then") or {}).get("policy_min")
        when = r.get("when") or {}
        condition = match_condition(when, idx)
        if not condition:
            continue

        missing = []
        for req in require:
            if isinstance(req, str):
                if ":" in req:
                    k, v = [s.strip() for s in req.split(":", 1)]
                    ok = match_condition({k: v}, idx)
                else:
                    ok = match_condition({"exists.true": req}, idx)
            elif isinstance(req, dict):
                ok = match_condition(req, idx)
            else:
                ok = False
            if not ok:
                missing.append(req)

        extra = {}
        if any(k in when for k in ["android.targetsdk.lt_policy_min"]) or policy_min:
            extra["policy_minimum"] = policy_min

        finding = {
            "id": rid,
            "platform": platform,
            "severity": severity,
            "status": "fail" if (missing or severity == "blocking") else "warn",
            "missing": missing,
            "because": because,
            "evidence": {
                "matched_when": when,
                "facts_used": {k: list(v) if isinstance(v, set) else v for k,v in idx.items() if k.startswith(platform)}
            }
        }
        if extra:
            finding["evidence"].update(extra)

        findings.append(finding)

    summary = {"blocking": 0, "advisory": 0, "fyi": 0}
    for f in findings:
        sev = f.get("severity", "advisory")
        summary[sev] = summary.get(sev, 0) + 1

    return {"version": version, "findings": findings, "summary": summary}

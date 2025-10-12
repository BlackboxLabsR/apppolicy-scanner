import json, pathlib, plistlib

SWIFT_EXTS = {".swift", ".m", ".mm", ".h"}
LOCKFILE_NAMES = {"Podfile.lock", "Package.resolved", "Cartfile", "Cartfile.resolved"}

COMMON_IOS_SDK_HINTS = [
    "AdSupport", "AppsFlyer", "Adjust", "FBSDK", "AppLovin", "UnityAds", "IronSource", "TikTok", "GoogleMobileAds"
]

def safe_load_plist(path: pathlib.Path):
    try:
        with path.open("rb") as f:
            return plistlib.load(f)
    except Exception:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

def scan_for_symbols(root: pathlib.Path, tokens):
    symbols = set()
    for p in root.rglob("*"):
        if p.is_file() and p.suffix in SWIFT_EXTS:
            try:
                txt = p.read_text(encoding="utf-8", errors="ignore")
                for t in tokens:
                    if t in txt:
                        symbols.add(t)
            except Exception:
                pass
    return sorted(symbols)

def read_lockfiles(root: pathlib.Path):
    text_blobs = []
    for name in LOCKFILE_NAMES:
        for p in root.rglob(name):
            try:
                text_blobs.append(p.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass
    joined = "\n".join(text_blobs)
    sdk_names = set()
    for hint in COMMON_IOS_SDK_HINTS:
        if hint.lower() in joined.lower():
            sdk_names.add(hint)
    for p in root.rglob("Package.resolved"):
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
            def collect_pkgs(obj):
                if isinstance(obj, dict):
                    for k,v in obj.items():
                        if k == "identity" and isinstance(v, str):
                            sdk_names.add(v)
                        collect_pkgs(v)
                elif isinstance(obj, list):
                    for it in obj: collect_pkgs(it)
            collect_pkgs(data)
        except Exception:
            pass
    return sorted(sdk_names)

def scan_ios(project_path: str):
    root = pathlib.Path(project_path)
    facts = {"platform":"ios","plist_keys":[],"entitlements":{},"privacy_manifest":{},"signals":{"auth_present":False,"sdk_names":[],"symbols":[]}}

    for plist in root.rglob("Info.plist"):
        data = safe_load_plist(plist)
        if isinstance(data, dict):
            for k in data.keys():
                if isinstance(k, str) and (k.startswith("NS") and k.endswith("UsageDescription")):
                    if k not in facts["plist_keys"]:
                        facts["plist_keys"].append(k)

    for ent in root.rglob("*.entitlements"):
        data = safe_load_plist(ent)
        if isinstance(data, dict):
            for k, v in data.items():
                facts["entitlements"][k] = v

    for man in root.rglob("PrivacyInfo.xcprivacy"):
        data = safe_load_plist(man)
        if isinstance(data, dict):
            facts["privacy_manifest"] = data

    sdk_names = read_lockfiles(root)
    facts["signals"]["sdk_names"] = sdk_names
    joined = " ".join(sdk_names).lower()
    auth_hints = ["firebaseauth", "appauth", "awsmobileclient", "auth0", "okta", "msal"]
    facts["signals"]["auth_present"] = any(h in joined for h in auth_hints)

    tokens = ["UIPasteboard", "ASIdentifierManager", "AVCaptureDevice", "UIImagePickerController"]
    symbols = scan_for_symbols(root, tokens)
    facts["signals"]["symbols"] = symbols

    facts["plist_keys"] = sorted(set(facts["plist_keys"]))
    return facts

import pathlib, re, xml.etree.ElementTree as ET

def scan_android(project_path: str):
    root = pathlib.Path(project_path)
    facts = {"platform":"android","permissions":[],"targetsdk":None,"deps":[]}

    for mf in root.rglob("AndroidManifest.xml"):
        try:
            tree = ET.parse(mf)
            for uses_perm in tree.findall(".//uses-permission"):
                name = uses_perm.attrib.get("{http://schemas.android.com/apk/res/android}name") or uses_perm.attrib.get("android:name")
                if name and name not in facts["permissions"]:
                    facts["permissions"].append(name)
        except Exception:
            pass

    for gradle in list(root.rglob("build.gradle")) + list(root.rglob("build.gradle.kts")):
        try:
            txt = gradle.read_text(encoding="utf-8", errors="ignore")
            m = re.search(r"targetSdk(?:Version)?\s*=?\s*(\d+)", txt)
            if m:
                facts["targetsdk"] = int(m.group(1))
                break
        except Exception:
            pass

    facts["permissions"] = sorted(set(facts["permissions"]))
    return facts

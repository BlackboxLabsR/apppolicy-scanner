# tests/test_pro_pack_verify.py
import io
import json
import tarfile
from pathlib import Path
import pytest
from nacl import signing, encoding, exceptions
from apcop.pro_pack import load_rules_pack

def _mk_pack(tmp_path: Path, rules: list[dict], sk: signing.SigningKey) -> Path:
    payload = json.dumps(
        {"version":"test","generated_at":0,"rules":rules,"format":"apppolicy-rules-pack@1"},
        separators=(",",":"), sort_keys=True
    ).encode()
    sig = sk.sign(payload).signature.hex()
    vk_hex = sk.verify_key.encode(encoder=encoding.HexEncoder).decode()
    p = tmp_path / "rules-pack-test.tar.gz"
    with tarfile.open(p, "w:gz") as tar:
        ti = tarfile.TarInfo("rules.json"); ti.size=len(payload); tar.addfile(ti, io.BytesIO(payload))
        b = sig.encode(); ti = tarfile.TarInfo("SIGNATURE.hex"); ti.size=len(b); tar.addfile(ti, io.BytesIO(b))
        b = vk_hex.encode(); ti = tarfile.TarInfo("PUBLIC_KEY.hex"); ti.size=len(b); tar.addfile(ti, io.BytesIO(b))
    return p

def test_pack_verify_ok(tmp_path, monkeypatch):
    sk = signing.SigningKey.generate()
    vk_hex = sk.verify_key.encode(encoder=encoding.HexEncoder).decode()
    rules = [{
        "id":"android.target_sdk.minimum",
        "platform":"android",
        "severity":"blocking",
        "when":{"all":[{"android.targetsdk.lt_policy_min":34}]},
        "because":{"source":"test","section":"Target API","url":"https://example.com"},
        "then":{"policy_min":34,"require":[]}
    }]
    pack = _mk_pack(tmp_path, rules, sk)
    monkeypatch.setenv("APPPOLICY_PUBKEY_HEX", vk_hex)
    doc = load_rules_pack(str(pack))
    assert doc["format"] == "apppolicy-rules-pack@1"
    assert doc["rules"][0]["id"] == "android.target_sdk.minimum"

def test_pack_verify_tampered_fails(tmp_path, monkeypatch):
    sk = signing.SigningKey.generate()
    vk_hex = sk.verify_key.encode(encoder=encoding.HexEncoder).decode()
    rules = [{"id":"dummy","platform":"android","severity":"fyi","when":{"all":[]},"then":{"require":[]}}]
    pack = _mk_pack(tmp_path, rules, sk)
    # rebuild with different rules.json but same SIGNATURE.hex to simulate tamper
    with tarfile.open(pack, "r:gz") as tar:
        sig_hex = tar.extractfile("SIGNATURE.hex").read().decode()
        pub_hex = tar.extractfile("PUBLIC_KEY.hex").read().decode()
    tampered_payload = json.dumps(
        {"version":"test","generated_at":0,"rules":[{"id":"tampered"}],"format":"apppolicy-rules-pack@1"},
        separators=(",",":"), sort_keys=True
    ).encode()
    bad = tmp_path / "rules-pack-bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tar:
        ti = tarfile.TarInfo("rules.json"); ti.size=len(tampered_payload); tar.addfile(ti, io.BytesIO(tampered_payload))
        b = sig_hex.encode(); ti = tarfile.TarInfo("SIGNATURE.hex"); ti.size=len(b); tar.addfile(ti, io.BytesIO(b))
        b = pub_hex.encode(); ti = tarfile.TarInfo("PUBLIC_KEY.hex"); ti.size=len(b); tar.addfile(ti, io.BytesIO(b))
    monkeypatch.setenv("APPPOLICY_PUBKEY_HEX", vk_hex)
    with pytest.raises(exceptions.BadSignatureError):
        load_rules_pack(str(bad))

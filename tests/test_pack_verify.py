import os, json, tarfile, base64, io
import pytest
from nacl import signing, encoding
from apcop.pro_pack import load_rules_pack

def _build_ephemeral_pack(tmpdir: str) -> str:
    """Build a minimal signed rules pack in tmpdir using APPPOLICY_PRIVATE_BASE64."""
    priv_b64 = os.environ.get("APPPOLICY_PRIVATE_BASE64")
    if not priv_b64:
        pytest.skip(
            "No APPPOLICY_TEST_PACK found and APPPOLICY_PRIVATE_BASE64 not set. "
            "Provide either APPPOLICY_TEST_PACK=/path/to/pack.tar.gz or APPPOLICY_PRIVATE_BASE64 to build one."
        )
    sk = signing.SigningKey(base64.b64decode(priv_b64))

    # Minimal canonical rules payload
    rules = {
        "version": "test",
        "generated_at": 0,
        "format": "apppolicy-rules-pack@1",
        "rules": [
            {
                "id": "example.min",
                "platform": "ios",
                "severity": "advisory",
                "when": {"any": [{"ios.plist.has": "NSCameraUsageDescription"}]},
                "because": {"section": "Example", "url": "https://example.com"}
            }
        ],
    }
    rules_bytes = json.dumps(rules, separators=(",", ":"), sort_keys=True).encode()
    sig_hex = sk.sign(rules_bytes).signature.hex()
    pub_hex = sk.verify_key.encode(encoder=encoding.HexEncoder).decode()

    pack_path = os.path.join(tmpdir, "rules-pack-ephemeral.tar.gz")
    with tarfile.open(pack_path, "w:gz") as tar:
        def add(name: str, data: bytes | str):
            b = data if isinstance(data, bytes) else data.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(b)
            tar.addfile(info, io.BytesIO(b))

        add("rules.json", rules_bytes)
        add("SIGNATURE.hex", sig_hex)
        add("PUBLIC_KEY.hex", pub_hex)

    # If caller didn't set APPPOLICY_PUBKEY_HEX, set it from the generated key
    os.environ.setdefault("APPPOLICY_PUBKEY_HEX", pub_hex)
    return pack_path

def test_signed_pack_ok(tmp_path):
    # Trusted pubkey must be set (either ahead of time or from ephemeral build)
    pub = os.environ.get("APPPOLICY_PUBKEY_HEX")

    pack = os.environ.get("APPPOLICY_TEST_PACK")
    if not pack:
        # Build ephemeral pack if a private key is available; else skip
        pack = _build_ephemeral_pack(str(tmp_path))
        # _build_ephemeral_pack sets APPPOLICY_PUBKEY_HEX if not set
        pub = os.environ.get("APPPOLICY_PUBKEY_HEX")

    assert pub, "APPPOLICY_PUBKEY_HEX must be set (or provided via ephemeral build)"
    assert os.path.exists(pack), f"Test rules pack not found: {pack}"

    rules_doc = load_rules_pack(pack)  # should raise on bad signature
    assert isinstance(rules_doc, dict) and "rules" in rules_doc and isinstance(rules_doc["rules"], list)

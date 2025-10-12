# apcop/pro_pack.py
import io, os, json, tarfile, urllib.request
from nacl import signing, encoding

TRUSTED_PUBKEY_HEX = os.getenv("APPPOLICY_PUBKEY_HEX", "").strip()  # set via env/Action input

def _load_bytes(path_or_url: str) -> bytes:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        with urllib.request.urlopen(path_or_url) as r:
            return r.read()
    return open(path_or_url, "rb").read()

def load_rules_pack(path_or_url: str) -> dict:
    raw = _load_bytes(path_or_url)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        rules = json.load(tar.extractfile("rules.json"))
        sig_hex = tar.extractfile("SIGNATURE.hex").read().decode().strip()
        # We verify with a trusted root pubkey (do NOT trust pack-embedded pubkeys)
        pub_hex = (TRUSTED_PUBKEY_HEX or "").lower()
        if not pub_hex:
            raise RuntimeError("APPPOLICY_PUBKEY_HEX is not set; cannot verify rules pack")
        vk = signing.VerifyKey(pub_hex, encoder=encoding.HexEncoder)
        vk.verify(json.dumps(rules).encode(), bytes.fromhex(sig_hex))
        return rules  # { "version": "...", "rules": [...] }

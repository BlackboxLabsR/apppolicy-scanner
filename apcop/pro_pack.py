import io, os, json, tarfile, urllib.request
from nacl import signing, encoding

TRUSTED_PUBKEY_HEX = os.getenv("APPPOLICY_PUBKEY_HEX", "").strip()

def _load_bytes(path_or_url: str) -> bytes:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        with urllib.request.urlopen(path_or_url) as r:
            return r.read()
    return open(path_or_url, "rb").read()

def load_rules_pack(path_or_url: str) -> dict:
    raw = _load_bytes(path_or_url)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        rules_bytes = tar.extractfile("rules.json").read()
        sig_hex     = tar.extractfile("SIGNATURE.hex").read().decode().strip()
        pack_pub    = tar.extractfile("PUBLIC_KEY.hex").read().decode().strip()

    # Prefer trusted root pubkey if provided, else fall back to pack-embedded pubkey.
    pub_hex = TRUSTED_PUBKEY_HEX or pack_pub
    vk = signing.VerifyKey(pub_hex, encoder=encoding.HexEncoder)

    # VERIFY EXACT BYTES THAT WERE SIGNED
    vk.verify(rules_bytes, bytes.fromhex(sig_hex))

    # Return the parsed rules
    return json.loads(rules_bytes)

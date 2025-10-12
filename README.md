# AppPolicy Scanner (open-source)

Local-first scanner that turns Apple/Google policy requirements into a release checklist tied to your iOS/Android manifests.

## Quickstart
```bash
pip install -e .
apppolicy scan-ios --project path/to/ios --out ios.json
apppolicy scan-android --project path/to/android --out android.json
apppolicy evaluate --facts ios.json android.json --rules rules/community.yaml --out report.json
apppolicy html --report report.json --out report.html
```
### Using Pro rule packs
Set the trusted public key for verification (ask us for the value):
```bash
export APPPOLICY_PUBKEY_HEX=<YOUR_PUBLIC_KEY_HEX>
apppolicy evaluate --facts ios.json android.json --rules-pack https://secure.example.com/rules-pack-2025.10.12.tar.gz --out report.json
```

## Notes
- Only *facts* (permissions/keys/SDK names) are processed; no source code leaves your machine.
- For Pro rule packs, see the commercial offering.

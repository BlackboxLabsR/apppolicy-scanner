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

## Notes
- Only *facts* (permissions/keys/SDK names) are processed; no source code leaves your machine.
- For Pro rule packs, see the commercial offering.

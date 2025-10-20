import argparse, json, pathlib
from .ios_scan import scan_ios
from .android_scan import scan_android
from .rules import evaluate_rules, load_rules
from .report import render_html
from .pro_pack import load_rules_pack

def main():
    p = argparse.ArgumentParser(prog="apppolicy", description="AppPolicy scanner & evaluator")
    sub = p.add_subparsers(dest="cmd", required=True)

    scani = sub.add_parser("scan-ios", help="Scan an iOS project")
    scani.add_argument("--project", required=True)
    scani.add_argument("--out", required=True)

    scana = sub.add_parser("scan-android", help="Scan an Android project")
    scana.add_argument("--project", required=True)
    scana.add_argument("--out", required=True)

    eva = sub.add_parser("evaluate", help="Evaluate facts against rules")
    eva.add_argument("--facts", nargs="+", required=True)
    g = eva.add_mutually_exclusive_group(required=True)
    g.add_argument("--rules", help="Path to community YAML rules")
    g.add_argument("--rules-pack", help="Path/URL to signed Pro rules pack (.tar.gz)")
    eva.add_argument("--out", required=True)

    htmlcmd = sub.add_parser("html", help="Render report.json to HTML")
    htmlcmd.add_argument("--report", required=True)
    htmlcmd.add_argument("--out", required=True)

    args = p.parse_args()

    if args.cmd == "scan-ios":
        facts = scan_ios(args.project)
        pathlib.Path(args.out).write_text(json.dumps(facts, indent=2))
        return
    if args.cmd == "scan-android":
        facts = scan_android(args.project)
        pathlib.Path(args.out).write_text(json.dumps(facts, indent=2))
        return
    if args.cmd == "evaluate":
        facts = [json.loads(pathlib.Path(f).read_text()) for f in args.facts]
        if getattr(args, "rules_pack", None):
            pack = load_rules_pack(args.rules_pack)
            rules_doc = {"version": pack.get("version","pack"), "rules": pack.get("rules",[])}
        else:
            rules_doc = load_rules(args.rules)
        report = evaluate_rules(facts, rules_doc)
        pathlib.Path(args.out).write_text(json.dumps(report, indent=2))
        return
    if args.cmd == "html":
        report = json.loads(pathlib.Path(args.report).read_text())
        out = render_html(report)
        pathlib.Path(args.out).write_text(out, encoding="utf-8")
        print(f"Wrote HTML report to {args.out}")
        return

import argparse, json, pathlib
from apcop.ios_scan import scan_ios
from apcop.android_scan import scan_android
from apcop.rules import evaluate_rules, load_rules
from apcop.report import render_html

def main():
    parser = argparse.ArgumentParser(prog="apppolicy", description="AppPolicy scanner & evaluator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scani = sub.add_parser("scan-ios", help="Scan an iOS project")
    scani.add_argument("--project", required=True)
    scani.add_argument("--out", required=True)

    scana = sub.add_parser("scan-android", help="Scan an Android project")
    scana.add_argument("--project", required=True)
    scana.add_argument("--out", required=True)

    eva = sub.add_parser("evaluate", help="Evaluate facts against rules")
    eva.add_argument("--facts", nargs="+", required=True, help="One or more facts_*.json from scanner")
    eva.add_argument("--rules", required=True, help="rules/community.yaml or a pro pack (compiled json)")
    eva.add_argument("--out", required=True, help="report.json output")

    html = sub.add_parser("html", help="Render report.json to HTML")
    html.add_argument("--report", required=True)
    html.add_argument("--out", required=True)

    args = parser.parse_args()

    if args.cmd == "scan-ios":
        facts = scan_ios(args.project)
        pathlib.Path(args.out).write_text(json.dumps(facts, indent=2))
        print(f"Wrote iOS facts to {args.out}")
    elif args.cmd == "scan-android":
        facts = scan_android(args.project)
        pathlib.Path(args.out).write_text(json.dumps(facts, indent=2))
        print(f"Wrote Android facts to {args.out}")
    elif args.cmd == "evaluate":
        facts = [json.loads(pathlib.Path(f).read_text()) for f in args.facts]
        rules = load_rules(args.rules)
        report = evaluate_rules(facts, rules)
        pathlib.Path(args.out).write_text(json.dumps(report, indent=2))
        print(f"Wrote report to {args.out}")
    elif args.cmd == "html":
        report = json.loads(pathlib.Path(args.report).read_text())
        html = render_html(report)
        pathlib.Path(args.out).write_text(html)
        print(f"Wrote HTML report to {args.out}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

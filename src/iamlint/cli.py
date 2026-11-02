"""Command line entry point.

    iamlint policies/                 # scan files or directories
    iamlint policy.json --json        # machine-readable report
    iamlint . --sarif out.sarif       # GitHub code scanning upload
    iamlint . --bundle                # treat every policy as one principal
    iamlint demo                      # the checked-in broken policies
    iamlint lab --out ./iam-lab       # six exercises
    iamlint rules --category trust    # the rule catalogue

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage or I/O error.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .analyze import Options, analyze_paths, analyze_text
from .demo import demo_text, run_demo
from .lab import check_lab, lab_files, lab_summary, write_lab
from .model import CATEGORIES, SEVERITIES, SEVERITY_RANK
from .render import render_compact, render_json, render_text
from .rules import RULES, rule_ids
from .sarif import render_sarif

SUBCOMMANDS = ("demo", "lab", "rules")

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iamlint",
        description="Audit AWS IAM policies with the line, column and bytes that prove each finding.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  iamlint policies/\n"
            "  iamlint policy.json --min-severity high\n"
            "  iamlint . --sarif iamlint.sarif --fail-on high\n"
            "  iamlint . --bundle --only escalation\n"
        ),
    )
    parser.add_argument("paths", nargs="*", help="policy JSON files or directories")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    parser.add_argument("--compact", action="store_true", help="one line per finding")
    parser.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 to FILE")
    parser.add_argument("--min-severity", default="info", choices=SEVERITIES, help="drop findings below this level")
    parser.add_argument("--fail-on", default="high", choices=[*SEVERITIES, "none"], help="exit 1 at or above this level")
    parser.add_argument("--ignore", metavar="RULES", default="", help="comma-separated rule ids to drop")
    parser.add_argument("--only", metavar="CATS", default="", help=f"keep only these categories: {', '.join(CATEGORIES)}")
    parser.add_argument("--skip", metavar="CATS", default="", help="drop these categories")
    parser.add_argument("--no-graph", action="store_true", help="skip pass 2 (combinations across statements)")
    parser.add_argument("--bundle", action="store_true", help="treat every input policy as attached to one principal")
    parser.add_argument("--no-recursive", action="store_true", help="do not walk directories")
    parser.add_argument("--quiet", action="store_true", help="suppress the report; useful with --sarif")
    parser.add_argument("--version", action="version", version=f"iamlint {__version__}")
    return parser


def _options_from(args: argparse.Namespace) -> Options:
    return Options(
        min_severity=args.min_severity,
        ignore={r.strip().upper() for r in args.ignore.split(",") if r.strip()},
        only={c.strip() for c in args.only.split(",") if c.strip()},
        skip={c.strip() for c in args.skip.split(",") if c.strip()},
        graph=not args.no_graph,
        bundle=args.bundle,
        follow_dirs=not args.no_recursive,
    )


def _exit_code(report, fail_on: str) -> int:
    if fail_on == "none":
        return EXIT_CLEAN
    floor = SEVERITY_RANK.get(fail_on, 0)
    for finding in report.findings:
        if SEVERITY_RANK.get(finding.severity, 0) <= floor:
            return EXIT_FINDINGS
    return EXIT_CLEAN


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.paths:
        # Reading a policy from stdin keeps it usable in a pipeline without
        # inventing a flag nobody remembers.
        if sys.stdin.isatty():
            print("iamlint: no paths given (try: iamlint demo)", file=sys.stderr)
            return EXIT_ERROR
        text = sys.stdin.read()
        report = analyze_text(text, "<stdin>", _options_from(args))
    else:
        missing = [p for p in args.paths if not os.path.exists(p)]
        if missing:
            print(f"iamlint: no such path: {missing[0]}", file=sys.stderr)
            return EXIT_ERROR
        report = analyze_paths(args.paths, _options_from(args))

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(render_sarif(report))
    if not args.quiet:
        if args.json:
            print(render_json(report))
        elif args.compact:
            print(render_compact(report))
        else:
            print(render_text(report))
    return _exit_code(report, args.fail_on)


def cmd_demo(args: argparse.Namespace) -> int:
    report = run_demo()
    if args.json:
        from .render import render_json as _render_json

        print(_render_json(report))
    else:
        print(demo_text())
    return _exit_code(report, "none")


def cmd_rules(args: argparse.Namespace) -> int:
    rows = []
    for rid in rule_ids():
        meta = RULES[rid]
        if args.category and meta.category != args.category:
            continue
        rows.append(
            {
                "id": rid,
                "severity": meta.severity,
                "category": meta.category,
                "title": meta.title,
                "ref": meta.ref,
            }
        )
    if args.json:
        import json as _json

        print(_json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(f"{row['id']}  {row['severity']:8}  {row['category']:11}  {row['title']}")
        print(f"\n{len(rows)} rules")
    return EXIT_CLEAN


def cmd_lab(args: argparse.Namespace) -> int:
    if args.out:
        written = write_lab(args.out)
        print(f"wrote {len(written)} files to {args.out}")
        for path in written:
            print(f"  {path}")
        target = args.out
    else:
        target = None
    report = check_lab(target)
    print(lab_summary(report))
    if args.json:
        from .render import render_json as _render_json

        print(_render_json(report))
    return EXIT_CLEAN if len(report.findings) >= len(lab_files()) else EXIT_FINDINGS


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()

    # Dispatch first: with nargs="*" on paths, argparse would otherwise swallow
    # "demo" as a file name.
    if argv and argv[0] in SUBCOMMANDS:
        command = argv[0]
        rest = argv[1:]
        if command == "demo":
            sub = argparse.ArgumentParser(prog="iamlint demo")
            sub.add_argument("--json", action="store_true")
            return cmd_demo(sub.parse_args(rest))
        if command == "rules":
            sub = argparse.ArgumentParser(prog="iamlint rules")
            sub.add_argument("--category", default="", choices=list(CATEGORIES))
            sub.add_argument("--json", action="store_true")
            return cmd_rules(sub.parse_args(rest))
        sub = argparse.ArgumentParser(prog="iamlint lab")
        sub.add_argument("--out", metavar="DIR", default="")
        sub.add_argument("--json", action="store_true")
        return cmd_lab(sub.parse_args(rest))

    args = parser.parse_args(argv)
    return cmd_scan(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

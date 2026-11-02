"""Orchestration: paths in, report out.

The order matters and is not incidental:

1. parse (a syntax error ends the analysis of that file - there are no
   statements to reason about)
2. pass 1, one statement at a time (:mod:`iamlint.rules`)
3. pass 2, combinations (:mod:`iamlint.graph`)
4. filter (severity floor, categories, ignore list)
5. dedupe and sort

Suppression is deliberately external to the policy. JSON has no comments, so
the usual ``# tool: ignore`` trick would make the file unparseable by AWS;
``--ignore`` and an ``.iamlint-ignore`` file are the honest alternatives.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from fnmatch import fnmatch

from .model import (
    INFO,
    SEVERITY_RANK,
    Finding,
    Loc,
    Policy,
    Report,
    make_finding,
)
from .parse import parse_file, parse_policy
from .rules import RULES, run_pass1

IGNORE_FILE = ".iamlint-ignore"


@dataclass
class Options:
    min_severity: str = INFO
    ignore: set[str] = field(default_factory=set)
    only: set[str] = field(default_factory=set)  # categories
    skip: set[str] = field(default_factory=set)  # categories
    graph: bool = True
    bundle: bool = False
    follow_dirs: bool = True

    def kept(self, finding: Finding) -> bool:
        if self.ignore and finding.rule in self.ignore:
            return False
        if SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK.get(self.min_severity, 0):
            return False
        if self.only and finding.category not in self.only:
            return False
        # The guards read as a checklist of reasons to drop a finding; folding
        # the last one into a boolean saves a line and costs the symmetry.
        return not (self.skip and finding.category in self.skip)


def collect_paths(paths: list[str], *, follow_dirs: bool = True) -> list[str]:
    """Expand directories into the JSON files under them."""
    out: list[str] = []
    for path in paths:
        if os.path.isdir(path):
            if not follow_dirs:
                continue
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "__pycache__")]
                for name in sorted(files):
                    if name.endswith(".json"):
                        out.append(os.path.join(root, name))
        else:
            out.append(path)
    return out


def load_ignore_file(path: str) -> set[str]:
    """``.iamlint-ignore`` lines: ``<path glob> <RULE[,RULE]> [# reason]``."""
    found: set[str] = set()
    if not os.path.isfile(path):
        return found
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            for name in parts[1].split(","):
                rule_id = name.strip().upper()
                if rule_id in RULES:
                    found.add(rule_id)
    return found


def ignore_for(paths: list[str], ignore_file: str = IGNORE_FILE) -> set[str]:
    """Ignore entries whose path glob matches any analysed file."""
    if not os.path.isfile(ignore_file):
        return set()
    out: set[str] = set()
    with open(ignore_file, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            pattern = parts[0]
            if any(fnmatch(p.replace(os.sep, "/"), pattern) or fnmatch(os.path.basename(p), pattern) for p in paths):
                for name in parts[1].split(","):
                    rule_id = name.strip().upper()
                    if rule_id in RULES:
                        out.add(rule_id)
    return out


def _parse_error_finding(policy: Policy) -> Finding:
    return make_finding(
        rule="IAM074",
        title=RULES["IAM074"].title,
        severity=RULES["IAM074"].severity,
        category="hygiene",
        file=policy.path,
        loc=Loc(path="", line=policy.error_line, col=policy.error_col),
        saw=f"{policy.parse_error}",
        fix="Fix the JSON: AWS rejects the whole document, not the one line.",
        ref=RULES["IAM074"].ref,
    )


def analyze_policies(policies: list[Policy], options: Options | None = None) -> Report:
    opts = options or Options()
    report = Report(policies=policies)
    raw: list[Finding] = []

    for policy in policies:
        if not policy.ok:
            raw.append(_parse_error_finding(policy))
            continue
        raw += run_pass1(policy)

    if opts.graph:
        from .graph import run_pass2, run_pass2_bundle

        if opts.bundle and len(policies) > 1:
            raw += run_pass2_bundle(policies)
        else:
            for policy in policies:
                if policy.ok:
                    raw += run_pass2(policy)

    kept: list[Finding] = []
    seen: set[tuple[str, str, int, int, str]] = set()
    for finding in raw:
        if not opts.kept(finding):
            report.suppressed += 1
            continue
        key = (finding.rule, finding.file, finding.line, finding.col, finding.pointer)
        if key in seen:
            report.suppressed += 1
            continue
        seen.add(key)
        kept.append(finding)

    kept.sort(key=lambda f: f.sort_key())
    report.findings = kept
    return report


def analyze_text(text: str, path: str = "<text>", options: Options | None = None) -> Report:
    policy = parse_policy(text, path)
    return analyze_policies([policy], options)


def analyze_paths(paths: list[str], options: Options | None = None) -> Report:
    opts = options or Options()
    files = collect_paths(paths, follow_dirs=opts.follow_dirs)
    if files:
        merged = set(opts.ignore)
        merged |= ignore_for(files)
        opts = Options(
            min_severity=opts.min_severity,
            ignore=merged,
            only=set(opts.only),
            skip=set(opts.skip),
            graph=opts.graph,
            bundle=opts.bundle,
            follow_dirs=opts.follow_dirs,
        )
    policies = [parse_file(path) for path in files]
    return analyze_policies(policies, opts)

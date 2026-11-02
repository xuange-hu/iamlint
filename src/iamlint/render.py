"""Output: text for humans, dicts for machines.

The text form is the product. Every finding prints as four lines - what it is,
where it is, what was there, what to do - so a reviewer can verify it against
the file without re-running anything. Findings that came from pass 2 print a
fifth line naming the second statement, because "delete one of these two" is
only actionable if you can see both.
"""

from __future__ import annotations

import json

from .model import SEVERITIES, Finding, Report

SEVERITY_TAG = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _tag(finding: Finding) -> str:
    return SEVERITY_TAG.get(finding.severity, finding.severity.upper())


def render_finding(finding: Finding) -> list[str]:
    lines = [
        f"[{_tag(finding)}] {finding.rule}  {finding.title}",
        f"    where : {finding.where}",
        f"    saw   : {finding.saw}",
    ]
    if finding.partner:
        lines.append(f"    with  : {finding.partner}")
    lines.append(f"    fix   : {finding.fix}")
    lines.append(f"    ref   : {finding.ref}")
    return lines


def render_text(report: Report) -> str:
    out: list[str] = []
    by_file: dict[str, list[Finding]] = {}
    for finding in report.findings:
        by_file.setdefault(finding.file, []).append(finding)

    for file in sorted(by_file):
        out.append(f"== {file}")
        for finding in by_file[file]:
            out += render_finding(finding)
            out.append("")

    if not report.findings:
        out.append("no findings")

    counts = report.counts()
    parts = " ".join(f"{name}={counts[name]}" for name in SEVERITIES if counts[name])
    out.append("--")
    out.append(
        f"{len(report.policies)} polic{'y' if len(report.policies) == 1 else 'ies'} scanned, "
        f"{len(report.findings)} finding{'' if len(report.findings) == 1 else 's'}"
        + (f" ({parts})" if parts else "")
        + f", grade {report.grade()}"
    )
    if report.suppressed:
        out.append(f"{report.suppressed} suppressed by severity floor, category filter or ignore list")
    return "\n".join(out)


def render_compact(report: Report) -> str:
    """One line per finding - for CI logs where four lines each is a wall."""
    return "\n".join(
        f"{finding.severity.upper():8} {finding.rule} {finding.file}:{finding.line}:{finding.col} {finding.title}"
        for finding in report.findings
    )


def finding_to_dict(finding: Finding) -> dict:
    return {
        "rule": finding.rule,
        "title": finding.title,
        "severity": finding.severity,
        "category": finding.category,
        "file": finding.file,
        "line": finding.line,
        "col": finding.col,
        "pointer": finding.pointer,
        "where": finding.where,
        "saw": finding.saw,
        "fix": finding.fix,
        "ref": finding.ref,
        "partner": finding.partner,
        "tags": list(finding.tags),
    }


def report_to_dict(report: Report) -> dict:
    return {
        "tool": "iamlint",
        "policies": [
            {
                "path": policy.path,
                "kind": policy.kind,
                "statements": len(policy.statements),
                "version": policy.version,
                "parse_error": policy.parse_error,
                "size": policy.size(),
            }
            for policy in report.policies
        ],
        "counts": report.counts(),
        "grade": report.grade(),
        "suppressed": report.suppressed,
        "rules_fired": sorted(report.rules_fired()),
        "findings": [finding_to_dict(f) for f in report.findings],
    }


def render_json(report: Report) -> str:
    return json.dumps(report_to_dict(report), indent=2, sort_keys=False)

"""SARIF 2.1.0 output, so findings land in GitHub code scanning.

The rule metadata is generated from :data:`iamlint.rules.RULES`, which means a
new rule shows up in SARIF without anyone remembering to add it here.
"""

from __future__ import annotations

import json

from .model import SEVERITY_RANK, Report
from .rules import RULES

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SARIF_RANK = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 1.0,
}


def rules_metadata() -> list[dict]:
    out = []
    for rule_id in sorted(RULES):
        meta = RULES[rule_id]
        out.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": meta.title},
                "fullDescription": {"text": meta.why or meta.title},
                "help": {"text": f"{meta.why or meta.title} Ref: {meta.ref}"},
                "defaultConfiguration": {"level": SARIF_LEVEL[meta.severity]},
                "properties": {
                    "tags": ["security", "iam", meta.category],
                    "precision": "high",
                    "security-severity": SARIF_RANK[meta.severity],
                },
            }
        )
    return out


def to_sarif(report: Report) -> dict:
    fired = sorted({f.rule for f in report.findings})
    results = []
    for finding in report.findings:
        # SARIF wants 1-based lines and a URI; relative paths keep the upload
        # small and are what code scanning expects for a repo checkout.
        uri = finding.file.replace("\\", "/")
        results.append(
            {
                "ruleId": finding.rule,
                "level": SARIF_LEVEL[finding.severity],
                "message": {
                    "text": f"{finding.title}. saw: {finding.saw}."
                    + (f" combined with {finding.partner}." if finding.partner else "")
                    + f" fix: {finding.fix}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {
                                "startLine": max(1, finding.line),
                                "startColumn": max(1, finding.col),
                                "snippet": {"text": finding.saw},
                            },
                        },
                        "logicalLocations": [{"name": finding.pointer}] if finding.pointer else [],
                    }
                ],
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "iamlint",
                        "informationUri": "https://github.com/xuange-hu/iamlint",
                        "semanticVersion": "0.1.0",
                        "rules": [r for r in rules_metadata() if r["id"] in fired],
                    }
                },
                "results": results,
                "properties": {
                    "grade": report.grade(),
                    "counts": report.counts(),
                },
            }
        ],
    }


def render_sarif(report: Report) -> str:
    return json.dumps(to_sarif(report), indent=2)


def worst_severity(report: Report) -> str | None:
    findings = report.findings
    if not findings:
        return None
    return min((f.severity for f in findings), key=lambda s: SEVERITY_RANK.get(s, 99))

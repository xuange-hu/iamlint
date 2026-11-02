"""SARIF: the upload is what makes findings show up in a pull request."""

from __future__ import annotations

import json

from helpers import doc, scan, statement

from iamlint.sarif import render_sarif, rules_metadata, to_sarif, worst_severity


def test_structure_is_sarif_21():
    report = scan(doc(statement(Sid="Admin", Action="*", Resource="*")))
    payload = to_sarif(report)
    assert payload["version"] == "2.1.0"
    assert payload["$schema"].endswith("sarif-schema-2.1.0.json")
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "iamlint"
    assert run["results"]


def test_only_fired_rules_are_declared():
    report = scan(doc(statement(Sid="Admin", Action="*", Resource="*")))
    declared = {r["id"] for r in to_sarif(report)["runs"][0]["tool"]["driver"]["rules"]}
    assert declared == report.rules_fired()


def test_result_carries_location_and_message():
    report = scan(doc(statement(Sid="Admin", Action="*", Resource="*")))
    result = to_sarif(report)["runs"][0]["results"][0]
    assert result["level"] == "error"
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "<test>"
    assert location["region"]["startLine"] >= 1
    assert "fix:" in result["message"]["text"]


def test_windows_paths_become_forward_slashes():
    report = scan(doc(statement(Sid="Admin", Action="*", Resource="*")))
    for finding in report.findings:
        finding.file = "policies\\prod\\admin.json"
    result = to_sarif(report)["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "policies/prod/admin.json"


def test_metadata_covers_every_rule_with_a_level():
    meta = {r["id"]: r for r in rules_metadata()}
    assert len(meta) == 49
    assert meta["IAM001"]["defaultConfiguration"]["level"] == "error"
    assert meta["IAM071"]["defaultConfiguration"]["level"] == "note"
    assert "security-severity" in meta["IAM001"]["properties"]


def test_render_sarif_is_valid_json():
    report = scan(doc(statement(Sid="Admin", Action="*", Resource="*")))
    json.loads(render_sarif(report))


def test_worst_severity_helper():
    assert worst_severity(scan(doc(statement(Sid="Admin", Action="*", Resource="*")))) == "critical"
    assert worst_severity(scan(doc(statement(Sid="Read", Action="s3:GetObject", Resource="arn:aws:s3:::a/b")))) in (None, "low")

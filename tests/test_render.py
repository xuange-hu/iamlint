"""Rendering: the four-line finding is the product, so it is asserted literally."""

from __future__ import annotations

import json

import pytest
from helpers import doc, dumps, one, scan, statement

from iamlint.render import finding_to_dict, render_compact, render_finding, render_json, render_text, report_to_dict


@pytest.fixture
def report():
    return scan(
        doc(
            statement(Sid="Admin", Action="*", Resource="*"),
            statement(Sid="Attach", Action="iam:AttachUserPolicy", Resource="*"),
        )
    )


def test_a_finding_renders_as_four_lines(report):
    finding = one(report, "IAM001")
    lines = render_finding(finding)
    assert lines[0].startswith("[CRIT] IAM001")
    assert lines[1].lstrip().startswith("where")
    assert lines[2].lstrip().startswith("saw")
    assert any(line.lstrip().startswith("fix") for line in lines)
    assert any(line.lstrip().startswith("ref") for line in lines)


def test_graph_findings_name_their_partner():
    report = scan(
        doc(
            statement(Sid="A", Action="iam:CreateAccessKey", Resource="*"),
            statement(Sid="B", Action="iam:AttachUserPolicy", Resource="*"),
        )
    )
    finding = one(report, "IAM030")
    lines = render_finding(finding)
    assert any(line.lstrip().startswith("with") for line in lines)


def test_text_report_groups_by_file_and_sums_up(report):
    out = render_text(report)
    assert out.startswith("== <test>")
    assert "grade F" in out
    assert "critical=1" in out


def test_empty_report_says_so():
    out = render_text(scan(dumps({"Version": "2012-10-17", "Statement": []})))
    assert "no findings" in out


def test_compact_is_one_line_each(report):
    lines = render_compact(report).splitlines()
    assert len(lines) == len(report.findings)
    assert "IAM001" in lines[0]


def test_json_round_trips(report):
    payload = json.loads(render_json(report))
    assert payload["findings"][0]["rule"] in {f.rule for f in report.findings}
    assert payload["grade"] == report.grade()
    assert payload["rules_fired"]


def test_report_dict_carries_policy_metadata(report):
    payload = report_to_dict(report)
    assert payload["policies"][0]["kind"] == "identity"
    assert payload["policies"][0]["statements"] == 2


def test_finding_dict_has_the_evidence_fields(report):
    data = finding_to_dict(one(report, "IAM001"))
    for key in ("rule", "severity", "category", "file", "line", "col", "pointer", "saw", "fix", "ref"):
        assert key in data


def test_suppressed_count_appears_in_the_summary():
    # one critical (IAM001) and one low (IAM071, no Sid): the low one is dropped
    text = doc(statement(Sid="Admin", Action="*", Resource="*"), statement(Action="s3:GetObject", Resource="*"))
    report = scan(text, min_severity="critical")
    assert "IAM071" not in report.rules_fired()
    assert report.suppressed >= 1
    assert "suppressed" in render_text(report)

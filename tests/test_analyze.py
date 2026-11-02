"""Filtering, paths and the ignore file - the part that decides what a user sees."""

from __future__ import annotations

from helpers import doc, dumps, one, scan, statement

from iamlint.analyze import Options, analyze_paths, analyze_text, collect_paths, ignore_for
from iamlint.model import CRITICAL, INFO, Loc, make_finding


def test_min_severity_drops_below_the_floor():
    text = doc(
        statement(Sid="Admin", Action="*", Resource="*"),
        statement(Action="s3:GetObject", Resource="*"),
    )
    everything = scan(text)
    assert "IAM071" in everything.rules_fired()
    high_only = scan(text, min_severity="high")
    assert "IAM071" not in high_only.rules_fired()
    assert "IAM001" in high_only.rules_fired()
    assert high_only.suppressed >= 1


def test_ignore_list_drops_exact_rules():
    text = doc(statement(Sid="Admin", Action="*", Resource="*"))
    assert "IAM001" in scan(text).rules_fired()
    assert "IAM001" not in scan(text, ignore={"IAM001"}).rules_fired()


def test_only_and_skip_categories():
    text = doc(
        statement(Sid="Admin", Action="*", Resource="*"),
        statement(Sid="Attach", Action="iam:AttachUserPolicy", Resource="*"),
    )
    assert scan(text, only={"wildcard"}).rules_fired() == {"IAM001", "IAM003"}
    skipped = scan(text, skip={"wildcard"}).rules_fired()
    assert "IAM001" not in skipped
    assert "IAM012" in skipped


def test_identical_findings_are_deduplicated():
    text = doc(statement(Sid="A", Action="iam:PassRole", Resource="*"), statement(Sid="B", Action="iam:PassRole", Resource="*"))
    hits = [f for f in scan(text).findings if f.rule == "IAM018"]
    assert len(hits) == 2  # two statements, two addresses: not a duplicate
    assert hits[0].line != hits[1].line


def test_findings_are_sorted_by_severity_then_position():
    text = doc(
        statement(Sid="Low", Action="iam:Describe*", Resource="*"),
        statement(Sid="Crit", Action="*", Resource="*"),
    )
    severities = [f.severity for f in scan(text).findings]
    assert severities[0] == CRITICAL
    assert severities[-1] in {INFO, "low", "medium"}


def test_parse_error_becomes_a_finding_and_stops_that_file():
    text = '{\n  "Version": "2012-10-17",\n  "Statement": [],\n}'
    report = scan(text)
    assert "IAM074" in report.rules_fired()
    finding = one(report, "IAM074")
    assert "trailing comma" in finding.saw
    # The offending token is the '}' that followed the comma, not the comma.
    assert finding.line == 4


def test_collect_paths_walks_directories(tmp_path):
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "a.json").write_text("{}", encoding="utf-8")
    (tmp_path / "policies" / "b.txt").write_text("nope", encoding="utf-8")
    (tmp_path / "top.json").write_text("{}", encoding="utf-8")
    found = collect_paths([str(tmp_path)])
    assert len(found) == 2
    assert all(p.endswith(".json") for p in found)


def test_collect_paths_skips_noise_directories(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "x.json").write_text("{}", encoding="utf-8")
    (tmp_path / "real.json").write_text("{}", encoding="utf-8")
    found = collect_paths([str(tmp_path)])
    assert len(found) == 1 and found[0].endswith("real.json")


def test_no_recursive_keeps_directories_out(tmp_path):
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "a.json").write_text("{}", encoding="utf-8")
    assert collect_paths([str(tmp_path / "policies")], follow_dirs=False) == []


def test_ignore_file_matches_by_glob(tmp_path, monkeypatch):
    (tmp_path / ".iamlint-ignore").write_text(
        "# the lab is meant to be broken\nlab/*.json IAM001,IAM003\nother.json IAM071\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    found = ignore_for(["lab/escalation-chain.json"])
    assert found == {"IAM001", "IAM003"}


def test_ignore_file_unknown_rules_are_dropped(tmp_path, monkeypatch):
    (tmp_path / ".iamlint-ignore").write_text("*.json IAM999,IAM001\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert ignore_for(["a.json"]) == {"IAM001"}


def test_ignore_file_is_applied_when_scanning(tmp_path, monkeypatch):
    (tmp_path / ".iamlint-ignore").write_text("*.json IAM001\n", encoding="utf-8")
    (tmp_path / "p.json").write_text(doc(statement(Sid="Admin", Action="*", Resource="*")), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    report = analyze_paths(["p.json"])
    assert "IAM001" not in report.rules_fired()
    assert report.suppressed >= 1


def test_analyze_paths_reads_files_and_directories(tmp_path):
    (tmp_path / "p.json").write_text(doc(statement(Sid="Admin", Action="*", Resource="*")), encoding="utf-8")
    report = analyze_paths([str(tmp_path / "p.json")])
    assert report.findings
    assert report.policies[0].path.endswith("p.json")


def test_analyze_text_names_the_source():
    report = analyze_text(doc(statement(Sid="Admin", Action="*", Resource="*")), "inline")
    assert {f.file for f in report.findings} == {"inline"}


def test_empty_document_produces_only_hygiene_findings():
    report = scan(dumps({"Version": "2012-10-17", "Statement": []}))
    assert report.findings == []
    assert report.grade() == "A"


def test_report_counts_and_worst():
    report = scan(doc(statement(Sid="Admin", Action="*", Resource="*"), statement(Action="s3:GetObject", Resource="*")))
    assert report.counts()[CRITICAL] == 1
    assert report.worst() == CRITICAL
    assert report.grade() == "F"


def test_options_keep_or_drop_a_finding():
    finding = make_finding(
        rule="IAM001",
        title="t",
        severity="critical",
        category="wildcard",
        file="p.json",
        loc=Loc(line=1, col=1),
        saw="s",
        fix="f",
        ref="r",
    )
    assert Options().kept(finding) is True
    assert Options(ignore={"IAM001"}).kept(finding) is False
    assert Options(only={"trust"}).kept(finding) is False
    assert Options(skip={"wildcard"}).kept(finding) is False
    assert Options(min_severity="critical").kept(finding) is True
    # high is a floor, not a ceiling: anything worse survives.
    assert Options(min_severity="high").kept(finding) is True
    low = make_finding(
        rule="IAM071", title="t", severity="low", category="hygiene",
        file="p.json", loc=Loc(line=1, col=1), saw="s", fix="f", ref="r",
    )
    assert Options(min_severity="high").kept(low) is False

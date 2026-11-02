"""CLI behaviour: exit codes are the contract CI depends on."""

from __future__ import annotations

import json

import pytest
from helpers import doc, statement

from iamlint.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main


@pytest.fixture
def policy_file(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(doc(statement(Sid="Admin", Action="*", Resource="*")), encoding="utf-8")
    return str(path)


def test_scan_reports_and_fails_on_high(policy_file, capsys):
    assert main([policy_file]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "IAM001" in out
    assert "where :" in out and "fix   :" in out


def test_fail_on_none_always_succeeds(policy_file, capsys):
    assert main([policy_file, "--fail-on", "none"]) == EXIT_CLEAN
    capsys.readouterr()


def test_min_severity_can_clear_the_exit_code(policy_file, capsys):
    assert main([policy_file, "--min-severity", "critical", "--fail-on", "critical"]) == EXIT_FINDINGS
    capsys.readouterr()


def test_json_output_is_parseable(policy_file, capsys):
    assert main([policy_file, "--json"]) == EXIT_FINDINGS
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"]
    assert payload["grade"] == "F"
    assert set(payload["counts"]) == {"critical", "high", "medium", "low", "info"}


def test_compact_output_is_one_line_per_finding(policy_file, capsys):
    main([policy_file, "--compact"])
    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert lines
    assert all(line.startswith(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) for line in lines)


def test_quiet_suppresses_the_report(policy_file, capsys):
    assert main([policy_file, "--quiet"]) == EXIT_FINDINGS
    assert capsys.readouterr().out == ""


def test_sarif_is_written(policy_file, tmp_path, capsys):
    out = str(tmp_path / "out.sarif")
    assert main([policy_file, "--sarif", out, "--quiet"]) == EXIT_FINDINGS
    with open(out, encoding="utf-8") as fh:
        payload = json.load(fh)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"]
    capsys.readouterr()


def test_missing_path_is_a_usage_error(tmp_path):
    assert main([str(tmp_path / "nope.json")]) == EXIT_ERROR


def test_no_paths_and_a_tty_is_a_usage_error(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert main([]) == EXIT_ERROR
    assert "no paths" in capsys.readouterr().err


def test_stdin_is_scanned(monkeypatch):
    text = doc(statement(Sid="Admin", Action="*", Resource="*"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("sys.stdin", type("S", (), {"read": staticmethod(lambda: text), "isatty": staticmethod(lambda: False)})())
    assert main(["--quiet"]) == EXIT_FINDINGS


def test_clean_policy_exits_zero(tmp_path, capsys):
    path = tmp_path / "clean.json"
    path.write_text(
        doc(statement(Sid="Read", Action="s3:GetObject", Resource="arn:aws:s3:::reports/*", Condition={"StringEquals": {"aws:PrincipalOrgID": "o-1"}})),
        encoding="utf-8",
    )
    assert main([str(path)]) == EXIT_CLEAN
    assert "no findings" in capsys.readouterr().out


def test_rules_subcommand_lists_the_catalogue(capsys):
    assert main(["rules"]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "IAM001" in out and "IAM075" in out


def test_rules_subcommand_filters_by_category(capsys):
    assert main(["rules", "--category", "trust"]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "IAM040" in out
    assert "IAM001" not in out


def test_rules_subcommand_json(capsys):
    assert main(["rules", "--json"]) == EXIT_CLEAN
    rows = json.loads(capsys.readouterr().out)
    assert rows and rows[0]["id"] == "IAM001"


def test_demo_subcommand(capsys):
    assert main(["demo"]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "no AWS call" in out
    assert "IAM001" in out


def test_demo_subcommand_json(capsys):
    assert main(["demo", "--json"]) == EXIT_CLEAN
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"]


def test_lab_writes_files_and_reports(tmp_path, capsys):
    out_dir = str(tmp_path / "lab")
    assert main(["lab", "--out", out_dir]) == EXIT_CLEAN
    printed = capsys.readouterr().out
    assert "escalation-chain.json" in printed
    assert (tmp_path / "lab" / "README.md").is_file()
    assert (tmp_path / "lab" / "confused-deputy.json").is_file()


def test_lab_checks_the_shipped_challenges(capsys):
    assert main(["lab"]) == EXIT_CLEAN
    assert "challenges detected" in capsys.readouterr().out


def test_ignore_flag_changes_the_exit_code(policy_file, capsys):
    assert main([policy_file, "--ignore", "IAM001,IAM003"]) == EXIT_CLEAN
    capsys.readouterr()


def test_version_flag_exits(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "iamlint" in capsys.readouterr().out


def test_directory_is_walked(tmp_path, capsys):
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "a.json").write_text(doc(statement(Sid="Admin", Action="*", Resource="*")), encoding="utf-8")
    assert main([str(tmp_path)]) == EXIT_FINDINGS
    capsys.readouterr()

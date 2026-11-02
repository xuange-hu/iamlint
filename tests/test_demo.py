"""The demo is the first thing a visitor runs. It has to be complete and honest."""

from __future__ import annotations

from helpers import scan

from iamlint.demo import DEMO_FILES, demo_text, missing_rules, run_demo
from iamlint.rules import rule_ids


def test_the_demo_reaches_every_rule():
    report = run_demo()
    assert missing_rules(report) == [], f"demo does not reach {missing_rules(report)}"


def test_the_demo_covers_the_whole_catalogue():
    assert len(rule_ids()) == 49
    assert len(run_demo().rules_fired()) == 49


def test_the_demo_is_deterministic():
    first = run_demo().findings
    second = run_demo().findings
    assert [f.rule for f in first] == [f.rule for f in second]
    assert [f.where for f in first] == [f.where for f in second]


def test_the_demo_text_mentions_the_offline_claim():
    assert "no AWS call" in demo_text()


def test_every_demo_file_parses_or_is_meant_not_to():
    """One file is the syntax-error case; the rest must parse."""
    report = run_demo()
    broken = [p for p in report.policies if not p.ok]
    assert len(broken) == 1
    assert broken[0].path.endswith("trailing-comma.json")


def test_the_demo_is_not_empty_and_not_a_firehose():
    report = run_demo()
    assert 50 < len(report.findings) < 200


def test_demo_files_are_named_after_what_they_are():
    assert set(DEMO_FILES) == {
        "demo/identity/ci-runner.json",
        "demo/resource/bucket-public.json",
        "demo/trust/github-actions.json",
        "demo/identity/condition-mistakes.json",
        "demo/identity/oversized.json",
        "demo/broken/trailing-comma.json",
    }


def test_the_scan_path_and_the_demo_path_agree():
    """Same engine, same verdict: the demo is not a special case."""
    text = DEMO_FILES["demo/resource/bucket-public.json"]
    assert "IAM004" in scan(text).rules_fired()

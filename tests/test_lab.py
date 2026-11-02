"""The lab must stay solved: a rule change that breaks it has to be visible."""

from __future__ import annotations

from pathlib import Path

from helpers import scan

from iamlint import lab
from iamlint.lab import LAB_NOTES, check_lab, lab_files, lab_readme, lab_summary, write_lab


def challenge(name: str) -> str:
    return (Path(lab.LAB_DIR) / name).read_text(encoding="utf-8")


def test_every_challenge_is_documented():
    assert set(LAB_NOTES) >= set(lab_files())


def test_write_lab_produces_the_files_and_a_readme(tmp_path):
    out = tmp_path / "iam-lab"
    written = write_lab(str(out))
    assert len(written) == len(lab_files()) + 1
    assert (out / "README.md").is_file()
    for name in lab_files():
        assert (out / name).is_file()


def test_the_readme_lists_every_challenge():
    readme = lab_readme()
    for name in lab_files():
        assert name in readme


def test_every_challenge_produces_a_finding():
    summary = lab_summary(check_lab())
    assert "MISS" not in summary
    assert f"{len(lab_files())}/{len(lab_files())} challenges detected" in summary


def test_shipped_challenges_are_all_json():
    assert lab_files()
    assert all(name.endswith(".json") for name in lab_files())


def test_escalation_chain_fires_the_graph_rule():
    assert "IAM030" in scan(challenge("escalation-chain.json")).rules_fired()


def test_syntax_challenge_is_a_parse_error():
    assert "IAM074" in scan(challenge("syntax-trap.json")).rules_fired()


def test_pass_role_challenge_is_code_execution():
    assert "IAM033" in scan(challenge("pass-role-lambda.json")).rules_fired()


def test_public_bucket_challenge_is_public():
    assert "IAM004" in scan(challenge("public-bucket.json")).rules_fired()


def test_confused_deputy_challenge_needs_external_id():
    fired = scan(challenge("confused-deputy.json")).rules_fired()
    assert {"IAM041", "IAM044"} & fired


def test_wildcard_challenge_flags_the_verb_wildcard():
    assert "IAM007" in scan(challenge("wildcard-verb.json")).rules_fired()

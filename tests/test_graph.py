"""Pass 2: the finding only exists between two statements.

These are the tests that matter most, because the whole claim of this tool is
that reading statements one at a time is not enough. Each test here would pass
against a scanner that only did pass 1 - that is the point: pass 1 cannot see
any of them.
"""

from __future__ import annotations

from helpers import doc, dumps, one, scan, statement

from iamlint.analyze import Options, analyze_policies
from iamlint.graph import paths
from iamlint.parse import parse_policy


def test_two_harmless_statements_become_an_escalation():
    text = doc(
        statement(Sid="One", Action="iam:CreateAccessKey", Resource="*"),
        statement(Sid="Two", Action="iam:AttachUserPolicy", Resource="*"),
    )
    report = scan(text)
    finding = one(report, "IAM030")
    assert finding.severity == "critical"
    assert "statement 0" in finding.saw and "statement 1" in finding.saw
    assert finding.partner, "a graph finding must name the second statement"


def test_a_single_statement_cannot_escalate_on_its_own():
    text = doc(statement(Sid="Only", Action=["iam:CreateAccessKey", "iam:AttachUserPolicy"], Resource="*"))
    report = scan(text)
    assert "IAM030" not in report.rules_fired()
    assert "IAM010" in report.rules_fired()
    assert "IAM012" in report.rules_fired()


def test_pass_role_plus_lambda_is_code_execution():
    text = doc(
        statement(Sid="A", Action="iam:PassRole", Resource="*"),
        statement(Sid="B", Action="lambda:UpdateFunctionCode", Resource="*"),
    )
    assert "IAM033" in scan(text).rules_fired()


def test_pass_role_plus_ec2_is_the_compute_variant():
    text = doc(
        statement(Sid="A", Action="iam:PassRole", Resource="*"),
        statement(Sid="B", Action="ec2:RunInstances", Resource="*"),
    )
    fired = scan(text).rules_fired()
    assert "IAM034" in fired
    assert "IAM033" not in fired


def test_policy_version_pair():
    text = doc(
        statement(Sid="A", Action="iam:CreatePolicyVersion", Resource="*"),
        statement(Sid="B", Action="iam:SetDefaultPolicyVersion", Resource="*"),
    )
    assert "IAM032" in scan(text).rules_fired()


def test_trust_rewrite_plus_assume():
    text = doc(
        statement(Sid="A", Action="iam:UpdateAssumeRolePolicy", Resource="*"),
        statement(Sid="B", Action="sts:AssumeRole", Resource="*"),
    )
    assert "IAM035" in scan(text).rules_fired()


def test_deny_breaks_the_pair():
    text = doc(
        statement(Sid="A", Action="iam:CreateAccessKey", Resource="*"),
        statement(Sid="B", Effect="Deny", Action="iam:AttachUserPolicy", Resource="*"),
    )
    assert "IAM030" not in scan(text).rules_fired()


def test_no_graph_option_removes_only_the_combination_findings():
    text = doc(
        statement(Sid="A", Action="iam:CreateAccessKey", Resource="*"),
        statement(Sid="B", Action="iam:AttachUserPolicy", Resource="*"),
    )
    with_graph = scan(text)
    without = scan(text, graph=False)
    assert "IAM030" in with_graph.rules_fired()
    assert "IAM030" not in without.rules_fired()
    assert "IAM010" in without.rules_fired()


def test_cross_policy_bundle_finds_what_one_file_cannot():
    """Split across two documents, the pair is invisible without --bundle."""
    first = parse_policy(doc(statement(Sid="A", Action="iam:CreateAccessKey", Resource="*")), "a.json")
    second = parse_policy(doc(statement(Sid="B", Action="iam:AttachUserPolicy", Resource="*")), "b.json")
    separate = analyze_policies([first, second], Options())
    assert "IAM030" not in separate.rules_fired()
    bundled = analyze_policies([first, second], Options(bundle=True))
    finding = one(bundled, "IAM030")
    assert "b.json" in finding.saw or "b.json" in finding.partner


def test_paths_returns_structured_pairs():
    policy = parse_policy(
        dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Sid": "A", "Effect": "Allow", "Action": "iam:CreateRole", "Resource": "*"},
                    {"Sid": "B", "Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": "*"},
                ],
            }
        )
    )
    found = paths([policy])
    assert found, "expected the create-role + inline-policy path"
    assert found[0].rule == "IAM031"
    assert found[0].first.index != found[0].second.index


def test_the_same_pair_is_reported_once():
    text = doc(
        statement(Sid="A", Action=["iam:CreateAccessKey", "iam:CreateAccessKey"], Resource="*"),
        statement(Sid="B", Action=["iam:AttachUserPolicy", "iam:AttachRolePolicy"], Resource="*"),
    )
    hits = [f for f in scan(text).findings if f.rule == "IAM030"]
    assert len(hits) == 1, [f.saw for f in hits]


def test_graph_ignores_unparseable_policies():
    broken = parse_policy("{", "broken.json")
    good = parse_policy(doc(statement(Sid="A", Action="iam:PassRole", Resource="*")), "good.json")
    report = analyze_policies([broken, good], Options())
    assert "IAM030" not in report.rules_fired()

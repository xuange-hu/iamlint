"""Parsing: IAM accepts shapes a strict reader would reject, and we have to read them."""

from __future__ import annotations

from helpers import doc, dumps, policy_of, statement

from iamlint.parse import parse_policy


def test_scalar_action_becomes_a_list():
    policy = parse_policy(doc(statement(Action="s3:GetObject", Resource="arn:aws:s3:::b/*")))
    stmt = policy.statements[0]
    assert [a.raw for a in stmt.actions] == ["s3:GetObject"]
    assert stmt.scalar_action is True


def test_list_action_keeps_its_elements():
    policy = parse_policy(doc(statement(Action=["s3:GetObject", "s3:PutObject"])))
    assert [a.raw for a in policy.statements[0].actions] == ["s3:GetObject", "s3:PutObject"]


def test_a_single_statement_object_is_wrapped():
    text = dumps({"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}})
    policy = parse_policy(text)
    assert len(policy.statements) == 1
    assert policy.statements[0].effect == "Allow"


def test_principal_star_string():
    policy = parse_policy(doc(statement(Principal="*", Resource="arn:aws:s3:::b/*")))
    principals = policy.statements[0].principals
    assert principals[0].kind == "*"
    assert principals[0].value == "*"


def test_principal_object_with_several_kinds():
    text = dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["111122223333", "arn:aws:iam::444455556666:root"], "Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    principals = parse_policy(text).statements[0].principals
    assert [(p.kind, p.value) for p in principals] == [
        ("AWS", "111122223333"),
        ("AWS", "arn:aws:iam::444455556666:root"),
        ("Service", "ec2.amazonaws.com"),
    ]


def test_conditions_are_normalised_to_lists():
    text = dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1", "aws:username": ["a", "b"]}},
                }
            ],
        }
    )
    conditions = parse_policy(text).statements[0].conditions
    assert conditions["StringEquals"]["aws:PrincipalOrgID"] == ["o-1"]
    assert conditions["StringEquals"]["aws:username"] == ["a", "b"]


def test_notaction_and_notresource():
    policy = parse_policy(doc(statement(NotAction=["s3:DeleteBucket"], NotResource=["arn:aws:s3:::b/private/*"])))
    stmt = policy.statements[0]
    assert [a.raw for a in stmt.not_actions] == ["s3:DeleteBucket"]
    assert [r.raw for r in stmt.not_resources] == ["arn:aws:s3:::b/private/*"]


def test_effect_is_case_normalised():
    policy = parse_policy(doc(statement(Effect="allow")))
    assert policy.statements[0].effect == "Allow"
    assert policy.statements[0].allows() is True
    assert parse_policy(doc(statement(Effect="Deny"))).statements[0].allows() is False


def test_kind_identity_has_no_principal():
    policy = parse_policy(doc(statement()))
    assert policy.kind == "identity"


def test_kind_trust_has_principal_and_assume():
    text = dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "111122223333"}, "Action": "sts:AssumeRole"}]}
    )
    assert parse_policy(text).kind == "trust"


def test_kind_resource_has_principal_and_resource():
    policy = parse_policy(doc(statement(Principal="*", Resource="arn:aws:s3:::b/*")))
    assert policy.kind == "resource"


def test_parse_error_is_captured_not_raised():
    policy = parse_policy('{"Version": "2012-10-17", "Statement": [],}')
    assert policy.ok is False
    assert "trailing comma" in policy.parse_error
    assert policy.error_line >= 1
    assert policy.statements == []


def test_version_and_id_and_sid():
    text = dumps({"Version": "2012-10-17", "Id": "p1", "Statement": [statement(Sid="S1")]})
    policy = parse_policy(text)
    assert policy.version == "2012-10-17"
    assert policy.id == "p1"
    assert policy.statements[0].sid == "S1"


def test_non_string_actions_are_skipped():
    text = dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": [1, "s3:GetObject"], "Resource": "*"}]})
    assert [a.raw for a in parse_policy(text).statements[0].actions] == ["s3:GetObject"]


def test_locations_point_at_the_action_value():
    text = '{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "iam:*",\n      "Resource": "*"\n    }\n  ]\n}\n'
    policy = parse_policy(text)
    stmt = policy.statements[0]
    assert stmt.actions[0].loc.line == 6
    assert stmt.actions[0].loc.path == "/Statement/0/Action"
    assert "iam:*" in stmt.actions[0].loc.snippet


def test_locations_carry_the_statement_pointer():
    policy = policy_of(doc(statement(), statement()))
    assert policy.statements[1].loc.path == "/Statement/1"


def test_empty_statement_list():
    policy = parse_policy(dumps({"Version": "2012-10-17", "Statement": []}))
    assert policy.statements == []
    assert policy.ok is True


def test_lowercase_keys_are_accepted():
    text = dumps({"version": "2012-10-17", "statement": [{"effect": "Allow", "action": "s3:GetObject", "resource": "*"}]})
    policy = parse_policy(text)
    assert policy.version == "2012-10-17"
    assert policy.statements[0].actions[0].raw == "s3:GetObject"

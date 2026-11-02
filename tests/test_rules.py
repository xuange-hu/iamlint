"""Every rule must be reachable, and every rule must stay quiet when it should.

The first half is a table: one minimal policy per rule id. It is deliberately
boring - if a rule cannot be triggered by ten lines of JSON, it is dead code
with a docstring. The second half is the negative space: the cases where a
rule must *not* fire, which is where scanners usually embarrass themselves.
"""

from __future__ import annotations

import json

import pytest
from helpers import doc, dumps, one, scan, statement

from iamlint.rules import SIZE_LIMIT_IDENTITY, rule_ids

TRIGGERS: dict[str, str] = {
    "IAM001": doc(statement(Sid="S", Action="*", Resource="*")),
    "IAM002": doc(statement(Sid="S", Action="iam:*", Resource="*")),
    "IAM003": doc(statement(Sid="S", Action=["s3:PutObject"], Resource="*")),
    "IAM004": doc(statement(Sid="S", Principal="*", Action="s3:GetObject", Resource="arn:aws:s3:::b/*")),
    "IAM005": doc(statement(Sid="S", NotAction=["s3:DeleteBucket"], Resource="*")),
    "IAM006": doc(statement(Sid="S", Action="s3:PutObject", NotResource=["arn:aws:s3:::b/p/*"])),
    "IAM007": doc(statement(Sid="S", Action="iam:Describe*", Resource="*")),
    "IAM008": doc(statement(Sid="S", Action="sts:AssumeRole", Resource="*")),
    "IAM010": doc(statement(Sid="S", Action="iam:CreateAccessKey", Resource="*")),
    "IAM011": doc(statement(Sid="S", Action="iam:CreateLoginProfile", Resource="*")),
    "IAM012": doc(statement(Sid="S", Action="iam:AttachUserPolicy", Resource="*")),
    "IAM013": doc(statement(Sid="S", Action="iam:PutUserPolicy", Resource="*")),
    "IAM014": doc(statement(Sid="S", Action="iam:AddUserToGroup", Resource="*")),
    "IAM015": doc(statement(Sid="S", Action="iam:UpdateAssumeRolePolicy", Resource="*")),
    "IAM016": doc(statement(Sid="S", Action="iam:CreatePolicyVersion", Resource="*")),
    "IAM017": doc(statement(Sid="S", Action="iam:SetDefaultPolicyVersion", Resource="*")),
    "IAM018": doc(statement(Sid="S", Action="iam:PassRole", Resource="*")),
    "IAM019": doc(statement(Sid="S", Action="iam:CreateRole", Resource="*")),
    "IAM020": doc(statement(Sid="S", Action="iam:DeleteRolePermissionsBoundary", Resource="*")),
    "IAM030": doc(
        statement(Sid="A", Action="iam:CreateAccessKey", Resource="*"),
        statement(Sid="B", Action="iam:AttachUserPolicy", Resource="*"),
    ),
    "IAM031": doc(
        statement(Sid="A", Action="iam:CreateRole", Resource="*"),
        statement(Sid="B", Action="iam:AttachRolePolicy", Resource="*"),
    ),
    "IAM032": doc(
        statement(Sid="A", Action="iam:CreatePolicyVersion", Resource="*"),
        statement(Sid="B", Action="iam:SetDefaultPolicyVersion", Resource="*"),
    ),
    "IAM033": doc(
        statement(Sid="A", Action="iam:PassRole", Resource="*"),
        statement(Sid="B", Action="lambda:CreateFunction", Resource="*"),
    ),
    "IAM034": doc(
        statement(Sid="A", Action="iam:PassRole", Resource="*"),
        statement(Sid="B", Action="ec2:RunInstances", Resource="*"),
    ),
    "IAM035": doc(
        statement(Sid="A", Action="iam:UpdateAssumeRolePolicy", Resource="*"),
        statement(Sid="B", Action="sts:AssumeRole", Resource="*"),
    ),
    "IAM036": doc(
        statement(Sid="A", Action="iam:CreateLoginProfile", Resource="*"),
        statement(Sid="B", Action="iam:AttachUserPolicy", Resource="*"),
    ),
    "IAM037": doc(
        statement(Sid="A", Action="iam:DeleteRolePermissionsBoundary", Resource="*"),
        statement(Sid="B", Action="iam:PutUserPolicy", Resource="*"),
    ),
    "IAM040": doc(statement(Sid="S", Principal={"AWS": "*"}, Action="sts:AssumeRole")),
    "IAM041": doc(statement(Sid="S", Principal={"AWS": "111122223333"}, Action="sts:AssumeRole")),
    "IAM042": doc(statement(Sid="S", Principal={"AWS": "arn:aws:iam::*:role/vendor"}, Action="sts:AssumeRole")),
    "IAM043": doc(statement(Sid="S", Principal={"AWS": "111122223333"}, Action="sts:AssumeRole")),
    "IAM044": doc(statement(Sid="S", Principal={"Service": "*.amazonaws.com"}, Action="sts:AssumeRole")),
    "IAM045": doc(
        statement(Sid="S", Principal={"Federated": "arn:aws:iam::123456789012:oidc-provider/tok"}, Action="sts:AssumeRoleWithWebIdentity")
    ),
    "IAM050": doc(
        statement(Sid="S", Action="s3:GetObject", Resource="*", Condition={"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}})
    ),
    "IAM051": doc(statement(Sid="S", Action="s3:GetObject", Resource="*", Condition={"StringLike": {"aws:username": "svc-*"}})),
    "IAM052": doc(statement(Sid="S", Action="iam:CreateAccessKey", Resource="*")),
    "IAM053": doc(
        statement(Sid="S", Action="s3:GetObject", Resource="*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}})
    ),
    "IAM054": doc(statement(Sid="S", Action="s3:GetObject", Resource="*", Condition={"Null": {"aws:PrincipalTag/team": "true"}})),
    "IAM060": doc({"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Sid": "S"}),
    "IAM061": doc(statement(Sid="S", Action="s3:PutObject", Resource=["analytics-bucket"])),
    "IAM062": doc(statement(Sid="S", Action=["secretsmanager:GetSecretValue"], Resource="*")),
    "IAM063": doc(statement(Sid="S", Action="s3:GetObject", Resource="arn:aws:s3:us-east-1:*:shared/*")),
    "IAM064": doc(statement(Sid="S", Action="s3:GetObject", Resource="arn:aws:s3:*:123456789012:shared/*")),
    "IAM070": doc(statement(Sid="S", Action="s3:GetObject", Resource="*"), version="2008-10-17"),
    "IAM071": doc(statement(Action="s3:GetObject", Resource="*")),
    "IAM072": doc(statement(Sid="Same", Action="s3:GetObject", Resource="*"), statement(Sid="Same", Action="s3:PutObject", Resource="*")),
    "IAM073": '{\n  "Version": "2012-10-17",\n  "Id": "a",\n  "Id": "b",\n  "Statement": []\n}',
    "IAM074": '{\n  "Version": "2012-10-17",\n  "Statement": [],\n}',
    "IAM075": dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "TenantLogs",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": [f"arn:aws:s3:::tenant-{i:03d}-logs/*" for i in range(140)],
                }
            ],
        }
    ),
}


def test_every_rule_has_a_trigger():
    assert set(TRIGGERS) == set(rule_ids()), set(rule_ids()) ^ set(TRIGGERS)


@pytest.mark.parametrize("rule", sorted(TRIGGERS))
def test_rule_fires_on_its_own_trigger(rule):
    report = scan(TRIGGERS[rule])
    assert rule in report.rules_fired(), f"{rule} did not fire on:\n{TRIGGERS[rule]}"


def test_findings_carry_where_saw_fix_ref():
    report = scan(TRIGGERS["IAM010"])
    finding = one(report, "IAM010")
    assert finding.where.startswith("<test>:")
    assert "iam:CreateAccessKey" in finding.saw
    assert finding.fix
    assert finding.ref
    assert finding.line >= 1


def test_deny_statements_produce_no_wildcard_findings():
    text = doc(statement(Sid="S", Effect="Deny", Action="*", Resource="*"))
    report = scan(text)
    assert "IAM001" not in report.rules_fired()
    assert "IAM003" not in report.rules_fired()


def test_service_wide_wildcard_does_not_list_every_primitive():
    """iam:* is one finding (IAM002), not eleven - the primitives are implied."""
    report = scan(doc(statement(Sid="S", Action="iam:*", Resource="*")))
    fired = report.rules_fired()
    assert "IAM002" in fired
    assert not (fired & {"IAM010", "IAM011", "IAM012", "IAM013"})


def test_iam062_and_iam003_do_not_double_report():
    """A write on '*' is IAM003; IAM062 owns the read-every-secret case."""
    write = scan(doc(statement(Sid="S", Action=["secretsmanager:PutSecretValue"], Resource="*")))
    assert "IAM003" in write.rules_fired()
    assert "IAM062" not in write.rules_fired()
    read = scan(doc(statement(Sid="S", Action=["secretsmanager:GetSecretValue"], Resource="*")))
    assert "IAM062" in read.rules_fired()
    assert "IAM003" not in read.rules_fired()


def test_external_id_suppresses_iam041():
    text = doc(
        statement(
            Sid="S",
            Principal={"AWS": "111122223333"},
            Action="sts:AssumeRole",
            Condition={"StringEquals": {"sts:ExternalId": "per-partner"}},
        )
    )
    assert "IAM041" not in scan(text).rules_fired()


def test_same_account_principal_suppresses_iam041():
    """The account is derived from the ARNs in the document, not guessed."""
    text = dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/peer"},
                    "Action": "sts:AssumeRole",
                },
                {
                    "Sid": "R",
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:us-east-1:123456789012:reports-2026/*",
                },
            ],
        }
    )
    assert "IAM041" not in scan(text).rules_fired()


def test_narrow_source_ip_does_not_fire_iam050():
    text = doc(statement(Sid="S", Action="s3:GetObject", Resource="*", Condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}))
    assert "IAM050" not in scan(text).rules_fired()


def test_mfa_true_does_not_fire_iam053():
    text = doc(statement(Sid="S", Action="s3:GetObject", Resource="*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}))
    assert "IAM053" not in scan(text).rules_fired()


def test_condition_present_suppresses_iam052():
    text = doc(
        statement(Sid="S", Action="iam:CreateAccessKey", Resource="*", Condition={"StringEquals": {"aws:PrincipalOrgID": "o-1"}})
    )
    assert "IAM052" not in scan(text).rules_fired()


def test_iam060_only_applies_to_identity_policies():
    trust = dumps({"Version": "2012-10-17", "Statement": [{"Sid": "S", "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]})
    assert "IAM060" not in scan(trust).rules_fired()


def test_missing_resource_still_fires_for_identity_policies():
    assert "IAM060" in scan(TRIGGERS["IAM060"]).rules_fired()


def test_size_rule_respects_the_limit():
    small = dumps({"Version": "2012-10-17", "Statement": [{"Sid": "S", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
    assert "IAM075" not in scan(small).rules_fired()
    assert len(TRIGGERS["IAM075"]) > SIZE_LIMIT_IDENTITY * 0.9


def test_clean_policy_is_clean():
    text = dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadOneBucket",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::reports-2026/*",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abcdef1234"}},
                }
            ],
        }
    )
    report = scan(text)
    assert report.findings == [], [f.rule for f in report.findings]
    assert report.grade() == "A"


def test_grade_reflects_the_worst_finding():
    assert scan(TRIGGERS["IAM001"]).grade() == "F"
    assert scan(TRIGGERS["IAM071"]).grade() == "B"


def test_rule_metadata_is_complete():
    for rid in rule_ids():
        from iamlint.rules import RULES

        meta = RULES[rid]
        assert meta.title and meta.severity and meta.category and meta.ref, rid


def test_severity_is_attached_to_the_finding():
    report = scan(TRIGGERS["IAM001"])
    finding = one(report, "IAM001")
    assert finding.severity == "critical"
    assert finding.category == "wildcard"


def test_json_pointer_travels_with_the_finding():
    report = scan(TRIGGERS["IAM001"])
    finding = one(report, "IAM001")
    assert finding.pointer == "/Statement/0/Action"


def test_demo_trigger_is_valid_json_when_it_parses():
    for rid, text in TRIGGERS.items():
        if rid in ("IAM073", "IAM074"):
            continue  # these two are the syntax-error cases
        json.loads(text)

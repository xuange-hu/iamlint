"""The demo: six policies that between them break every rule.

It is checked in as text and needs no AWS account, no credentials and no
network - ``iamlint demo`` is the first command a visitor runs and it has to
work on a plane. The six files are also the contract test: if a rule cannot be
reached from the demo, either the rule is unreachable in practice or the demo
is lying about what the tool does.
"""

from __future__ import annotations

import json

from .analyze import Options, analyze_policies
from .model import Report
from .parse import parse_policy
from .render import render_text
from .rules import rule_ids

# 1. An identity policy written by someone in a hurry: service-wide wildcards,
#    every escalation primitive in the table, wildcard regions and accounts.
DEMO_IDENTITY = """{
  "Version": "2008-10-17",
  "Id": "ci-runner",
  "Id": "ci-runner-final",
  "Statement": [
    {
      "Sid": "AdminEverything",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Sid": "IamAdmin",
      "Effect": "Allow",
      "Action": "iam:*",
      "Resource": "*"
    },
    {
      "Sid": "MintKeys",
      "Effect": "Allow",
      "Action": "iam:CreateAccessKey",
      "Resource": "*"
    },
    {
      "Sid": "ConsolePassword",
      "Effect": "Allow",
      "Action": ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"],
      "Resource": "*"
    },
    {
      "Sid": "AttachPolicies",
      "Effect": "Allow",
      "Action": ["iam:AttachUserPolicy", "iam:AttachRolePolicy"],
      "Resource": "*"
    },
    {
      "Sid": "InlinePolicies",
      "Effect": "Allow",
      "Action": "iam:PutUserPolicy",
      "Resource": "*"
    },
    {
      "Sid": "GroupMembership",
      "Effect": "Allow",
      "Action": "iam:AddUserToGroup",
      "Resource": "*"
    },
    {
      "Sid": "TrustRewrite",
      "Effect": "Allow",
      "Action": "iam:UpdateAssumeRolePolicy",
      "Resource": "*"
    },
    {
      "Sid": "VersionBump",
      "Effect": "Allow",
      "Action": "iam:CreatePolicyVersion",
      "Resource": "*"
    },
    {
      "Sid": "VersionActivate",
      "Effect": "Allow",
      "Action": "iam:SetDefaultPolicyVersion",
      "Resource": "*"
    },
    {
      "Sid": "PassAnyRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "*"
    },
    {
      "Sid": "MakeRole",
      "Effect": "Allow",
      "Action": "iam:CreateRole",
      "Resource": "*"
    },
    {
      "Sid": "DropBoundary",
      "Effect": "Allow",
      "Action": "iam:DeleteRolePermissionsBoundary",
      "Resource": "*"
    },
    {
      "Sid": "LambdaWrite",
      "Effect": "Allow",
      "Action": ["lambda:CreateFunction", "lambda:UpdateFunctionCode"],
      "Resource": "*"
    },
    {
      "Sid": "RunInstances",
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": "*"
    },
    {
      "Sid": "AssumeAnyRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "*"
    },
    {
      "Sid": "VerbWildcard",
      "Effect": "Allow",
      "Action": "iam:Describe*",
      "Resource": "*"
    },
    {
      "Sid": "DuplicateSid",
      "Effect": "Allow",
      "Action": "cloudwatch:PutMetricData"
    },
    {
      "Sid": "DuplicateSid",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": ["analytics-bucket"]
    },
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "secretsmanager:GetSecretValue"],
      "Resource": "*"
    },
    {
      "Sid": "WildcardAccount",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:iam::*:role/backup-reader"
    },
    {
      "Sid": "WildcardRegion",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:*:123456789012:logs-bucket/*"
    }
  ]
}
"""

# 2. A bucket policy that is public and uses inverted lists.
DEMO_RESOURCE = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::demo-public-bucket/*"
    },
    {
      "Sid": "InvertedActions",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "NotAction": ["s3:DeleteBucket", "s3:PutBucketPolicy"],
      "Resource": "*"
    },
    {
      "Sid": "EverythingExceptOne",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:PutObject",
      "NotResource": "arn:aws:s3:::demo-public-bucket/private/*"
    }
  ]
}
"""

# 3. A trust policy that trusts almost everyone, several different ways.
DEMO_TRUST = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AnyoneCanAssume",
      "Effect": "Allow",
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "PartnerNoExternalId",
      "Effect": "Allow",
      "Principal": {"AWS": "111122223333"},
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "AnyAccountRole",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::*:role/vendor-reader"},
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "AnyService",
      "Effect": "Allow",
      "Principal": {"Service": "*.amazonaws.com"},
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "GitHubOidc",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity"
    }
  ]
}
"""

# 4. Conditions that read like controls and are not.
DEMO_CONDITIONS = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FromAnywhere",
      "Effect": "Allow",
      "Action": "iam:AttachUserPolicy",
      "Resource": "*",
      "Condition": {"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}}
    },
    {
      "Sid": "NameLike",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*",
      "Condition": {"StringLike": {"aws:username": "svc-*"}}
    },
    {
      "Sid": "NoMfaRequired",
      "Effect": "Allow",
      "Action": "iam:CreateAccessKey",
      "Resource": "*",
      "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}
    },
    {
      "Sid": "TagCanBeAbsent",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": {"Null": {"aws:PrincipalTag/team": "true"}}
    }
  ]
}
"""

# 5. What a policy looks like three years of "just add one more bucket" later.
DEMO_BROKEN = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Typo",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*",
    }
  ]
}
"""


def _oversized_policy() -> str:
    """Built deterministically: 140 enumerated buckets, the way real ones grow."""
    resources = [f"arn:aws:s3:::tenant-{i:03d}-logs/*" for i in range(140)]
    body = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TenantLogs",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": resources,
            }
        ],
    }
    return json.dumps(body, indent=2)


DEMO_OVERSIZED = _oversized_policy()

DEMO_FILES: dict[str, str] = {
    "demo/identity/ci-runner.json": DEMO_IDENTITY,
    "demo/resource/bucket-public.json": DEMO_RESOURCE,
    "demo/trust/github-actions.json": DEMO_TRUST,
    "demo/identity/condition-mistakes.json": DEMO_CONDITIONS,
    "demo/identity/oversized.json": DEMO_OVERSIZED,
    "demo/broken/trailing-comma.json": DEMO_BROKEN,
}


def demo_policies() -> list:
    return [parse_policy(text, name) for name, text in DEMO_FILES.items()]


def run_demo(options: Options | None = None) -> Report:
    """Analyse the checked-in demo set. No I/O, no network, same code path as the CLI."""
    return analyze_policies(demo_policies(), options or Options())


def missing_rules(report: Report) -> list[str]:
    """Rules the demo no longer reaches - the contract the CI enforces."""
    fired = report.rules_fired()
    return [rid for rid in rule_ids() if rid not in fired]


def demo_text() -> str:
    report = run_demo()
    lines = [render_text(report), "", "the demo read only checked-in text: no AWS call, no credentials, no network"]
    missing = missing_rules(report)
    if missing:
        lines.append(f"RULES NOT REACHED BY THE DEMO: {', '.join(missing)}")
    return "\n".join(lines)

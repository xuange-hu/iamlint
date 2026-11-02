"""Action and ARN pattern matching, plus the table of privileged actions.

IAM matching rules that matter and are easy to get wrong:

* action matching is case-insensitive (``iam:CreateAccessKey`` ==
  ``iam:createaccesskey`` in the AWS evaluation engine);
* ``*`` and ``?`` are globs, not regexes - ``iam:Put*Policy`` matches
  ``iam:PutUserPolicy`` but a dot is still a literal dot;
* a wildcard in the middle of a verb is legal and is what makes
  ``iam:*AccessKey`` dangerous;
* ARN sections are positional, so ``arn:aws:iam::*:role/admin`` is a wildcard
  on the account, not on the role name.

This module is pure: no parsing, no I/O, no findings.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from dataclasses import dataclass

WILDCARD_NONE = "none"
WILDCARD_FULL = "full"
WILDCARD_PREFIX = "prefix"
WILDCARD_SUFFIX = "suffix"
WILDCARD_INNER = "inner"


def classify(pattern: str) -> str:
    """Which kind of wildcard a pattern carries."""
    if pattern == "*":
        return WILDCARD_FULL
    if "*" not in pattern and "?" not in pattern:
        return WILDCARD_NONE
    if pattern.endswith("*") and "*" not in pattern[:-1] and "?" not in pattern:
        return WILDCARD_PREFIX
    if pattern.startswith("*") and "*" not in pattern[1:] and "?" not in pattern:
        return WILDCARD_SUFFIX
    return WILDCARD_INNER


def matches(pattern: str, value: str) -> bool:
    """Case-insensitive glob match, the way IAM evaluates an action pattern."""
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


def any_match(patterns: Iterable[str], value: str) -> bool:
    return any(matches(p, value) for p in patterns)


def covers(policy_pattern: str, catalog_action: str) -> bool:
    """Does a policy pattern grant a catalog action?

    Both sides may carry wildcards - the policy can say ``iam:Put*`` and the
    catalog can say ``iam:Put*Policy`` - so the match has to be tried in both
    directions. A one-directional test is the classic reason a scanner misses
    ``iam:Put*``, which grants every Put*Policy primitive.
    """
    return matches(policy_pattern, catalog_action) or matches(catalog_action, policy_pattern)


def is_service_wide(action: str) -> bool:
    """``*``, ``*:*``, ``iam:*`` - patterns that already have their own rule.

    Service-wide patterns grant every primitive in the service, so feeding them
    into the primitive table would produce eleven findings for one line. IAM001
    and IAM002 own those.
    """
    raw = action.strip()
    if raw in ("*", "*:*"):
        return True
    service, verb = split_action(raw)
    return service == "*" or verb == "*"


def split_action(action: str) -> tuple[str, str]:
    """``iam:CreateAccessKey`` -> ``("iam", "CreateAccessKey")``."""
    if ":" in action:
        service, _, verb = action.partition(":")
        return service.lower(), verb
    return action.lower(), ""


def service_of(action: str) -> str:
    return split_action(action)[0]


def expand_known(pattern: str, catalog: Iterable[str]) -> list[str]:
    """Concrete catalog actions a pattern grants. Used by the graph pass."""
    return sorted({a for a in catalog if matches(pattern, a)})


def is_read_only(action: str) -> bool:
    """Get/List/Describe/Read - the actions a wildcard resource usually forgives."""
    verb = split_action(action)[1].lower()
    return verb.startswith(("get", "list", "describe", "read", "head", "search", "view"))


def is_write(action: str) -> bool:
    return not is_read_only(action)


def arn_sections(arn: str) -> list[str]:
    """``arn:aws:s3:::bucket/key`` -> ``["arn", "aws", "s3", "", "", "bucket/key"]``."""
    if not arn.startswith("arn:"):
        return []
    return arn.split(":", 5)


def arn_account(arn: str) -> str:
    parts = arn_sections(arn)
    return parts[4] if len(parts) > 4 else ""


def arn_service(arn: str) -> str:
    parts = arn_sections(arn)
    return parts[2] if len(parts) > 2 else ""


def arn_resource_part(arn: str) -> str:
    parts = arn_sections(arn)
    return parts[5] if len(parts) > 5 else ""


def resource_has_wildcard_arn(arn: str) -> bool:
    """True when an otherwise-ARN-shaped resource hides a wildcard anywhere."""
    return arn.startswith("arn:") and ("*" in arn or "?" in arn)


def cidr_is_broad(value: str) -> bool:
    """A /0 or /8 source-IP condition is not a restriction anyone should trust."""
    value = value.strip()
    if "/" not in value:
        return False  # plain IP; leave it alone
    bits = value.rsplit("/", 1)[1]
    try:
        return int(bits) <= 8
    except ValueError:
        return True  # unparseable mask: treat as broken, not as safe


@dataclass(frozen=True)
class Primitive:
    """A single IAM capability that escalation paths are built from."""

    key: str
    rule: str
    patterns: tuple[str, ...]
    title: str
    why: str


# The primitives. Ordering is irrelevant; the graph pass looks them up by key.
PRIMITIVES: tuple[Primitive, ...] = (
    Primitive(
        key="create_access_key",
        rule="IAM010",
        patterns=("iam:CreateAccessKey", "iam:*AccessKey*"),
        title="can mint another identity's access key",
        why="CreateAccessKey on a user or role other than your own is a credential-theft primitive.",
    ),
    Primitive(
        key="login_profile",
        rule="IAM011",
        patterns=("iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:*LoginProfile"),
        title="can set or reset a console password",
        why="Writing a login profile turns a programmatic foothold into console access.",
    ),
    Primitive(
        key="attach_managed",
        rule="IAM012",
        patterns=("iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy", "iam:Attach*Policy"),
        title="can attach a managed policy",
        why="Attaching AdministratorAccess to yourself is the shortest escalation there is.",
    ),
    Primitive(
        key="put_inline",
        rule="IAM013",
        patterns=("iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy", "iam:Put*Policy"),
        title="can write an inline policy",
        why="An inline policy can grant anything, and it does not show up in managed-policy reviews.",
    ),
    Primitive(
        key="add_to_group",
        rule="IAM014",
        patterns=("iam:AddUserToGroup",),
        title="can add a user to a group",
        why="Adding yourself to an admin group inherits whatever that group has.",
    ),
    Primitive(
        key="update_trust",
        rule="IAM015",
        patterns=("iam:UpdateAssumeRolePolicy",),
        title="can rewrite a role's trust policy",
        why="Rewriting who may assume a role lets you assume it yourself.",
    ),
    Primitive(
        key="create_policy_version",
        rule="IAM016",
        patterns=("iam:CreatePolicyVersion",),
        title="can create a new policy version",
        why="A new version can be anything; the damage lands when it is made default.",
    ),
    Primitive(
        key="set_default_version",
        rule="IAM017",
        patterns=("iam:SetDefaultPolicyVersion",),
        title="can make a policy version the default",
        why="This is the step that activates a policy version someone else wrote.",
    ),
    Primitive(
        key="pass_role",
        rule="IAM018",
        patterns=("iam:PassRole",),
        title="can pass a role to a service",
        why="PassRole plus anything that runs code is the classic lateral move.",
    ),
    Primitive(
        key="create_role",
        rule="IAM019",
        patterns=("iam:CreateRole",),
        title="can create a role",
        why="A fresh role with a trust policy you control is a clean backdoor.",
    ),
    Primitive(
        key="delete_boundary",
        rule="IAM020",
        patterns=("iam:DeleteRolePermissionsBoundary", "iam:DeleteUserPermissionsBoundary", "iam:PutRolePermissionsBoundary"),
        title="can remove a permissions boundary",
        why="Boundaries are the only thing capping what the role may ever do.",
    ),
)

# Services that execute code or accept a role; combined with PassRole they turn
# a permissions problem into remote code execution on a compute principal.
PASS_ROLE_CONSUMERS: tuple[str, ...] = (
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
    "ecs:RunTask",
    "ecs:StartTask",
    "glue:CreateDevEndpoint",
    "glue:CreateJob",
    "glue:UpdateJob",
    "cloudformation:CreateStack",
    "cloudformation:UpdateStack",
    "datapipeline:CreatePipeline",
    "sagemaker:Create*",
    "codebuild:CreateProject",
    "codebuild:UpdateProject",
    "states:CreateStateMachine",
)

SENSITIVE_SERVICES: tuple[str, ...] = ("iam", "sts", "kms", "secretsmanager", "ssm", "organizations", "account")


def primitive_for(action: str) -> Primitive | None:
    """The first primitive an action pattern feeds, if any.

    Service-wide patterns return ``None``: they are IAM001/IAM002's job, and
    listing eleven primitives for ``iam:*`` would bury the one thing a reviewer
    needs to see.
    """
    if is_service_wide(action):
        return None
    for prim in PRIMITIVES:
        if any(covers(action, p) for p in prim.patterns):
            return prim
    return None

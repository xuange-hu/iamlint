"""Matching semantics. Getting these wrong is how a scanner misses iam:Put*."""

from __future__ import annotations

import pytest

from iamlint.wildcard import (
    WILDCARD_FULL,
    WILDCARD_INNER,
    WILDCARD_NONE,
    WILDCARD_PREFIX,
    WILDCARD_SUFFIX,
    arn_account,
    arn_resource_part,
    arn_service,
    cidr_is_broad,
    classify,
    covers,
    expand_known,
    is_read_only,
    is_service_wide,
    is_write,
    matches,
    primitive_for,
    service_of,
    split_action,
)


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("s3:GetObject", WILDCARD_NONE),
        ("*", WILDCARD_FULL),
        ("iam:*", WILDCARD_PREFIX),
        ("*AccessKey", WILDCARD_SUFFIX),
        ("iam:Create*", WILDCARD_PREFIX),
        ("iam:*AccessKey*", WILDCARD_INNER),
        ("iam:Cr?ateAccessKey", WILDCARD_INNER),
    ],
)
def test_classify(pattern, expected):
    assert classify(pattern) == expected


def test_matches_is_case_insensitive():
    assert matches("iam:CreateAccessKey", "iam:createaccesskey")
    assert matches("iam:Create*", "iam:CreateRole")
    assert not matches("iam:CreateAccessKey", "iam:CreateRole")


def test_covers_works_in_both_directions():
    # The policy pattern is the left side; the catalogue entry may also be a glob.
    assert covers("iam:Put*", "iam:PutUserPolicy")
    assert covers("iam:CreateAccessKey", "iam:*AccessKey*")
    assert covers("*", "iam:CreateAccessKey")
    assert not covers("iam:Put*", "iam:AttachUserPolicy")


def test_service_wide_patterns_are_recognised():
    assert is_service_wide("*")
    assert is_service_wide("iam:*")
    assert is_service_wide("*:*")
    assert not is_service_wide("iam:Create*")
    assert not is_service_wide("s3:GetObject")


def test_split_action():
    assert split_action("iam:CreateAccessKey") == ("iam", "CreateAccessKey")
    assert service_of("S3:GetObject") == "s3"
    assert split_action("nocolon") == ("nocolon", "")


@pytest.mark.parametrize(
    ("action", "read_only"),
    [("s3:GetObject", True), ("iam:ListRoles", True), ("ec2:DescribeInstances", True), ("s3:PutObject", False), ("iam:CreateRole", False), ("kms:Decrypt", False)],
)
def test_read_only_verbs(action, read_only):
    assert is_read_only(action) is read_only
    assert is_write(action) is not read_only


def test_arn_sections():
    assert arn_service("arn:aws:s3:::bucket/key") == "s3"
    assert arn_account("arn:aws:iam::123456789012:role/x") == "123456789012"
    assert arn_account("arn:aws:iam::*:role/x") == "*"
    assert arn_resource_part("arn:aws:iam::123456789012:role/x") == "role/x"
    assert arn_account("not-an-arn") == ""


@pytest.mark.parametrize(
    ("cidr", "broad"),
    [("0.0.0.0/0", True), ("10.0.0.0/8", True), ("203.0.113.0/24", False), ("192.168.1.1", False), ("1.2.3.0/bad", True)],
)
def test_cidr_is_broad(cidr, broad):
    assert cidr_is_broad(cidr) is broad


def test_primitive_for_maps_actions_to_primitives():
    assert primitive_for("iam:CreateAccessKey").key == "create_access_key"
    assert primitive_for("iam:AttachUserPolicy").key == "attach_managed"
    assert primitive_for("iam:Put*").key == "put_inline"
    assert primitive_for("iam:PassRole").key == "pass_role"
    assert primitive_for("s3:GetObject") is None


def test_primitive_for_ignores_service_wide_patterns():
    """iam:* is IAM002's job; listing eleven primitives for it would bury the point."""
    assert primitive_for("iam:*") is None
    assert primitive_for("*") is None


def test_expand_known_lists_catalog_matches():
    catalog = ["iam:PutUserPolicy", "iam:PutRolePolicy", "iam:AttachUserPolicy"]
    assert expand_known("iam:Put*", catalog) == ["iam:PutRolePolicy", "iam:PutUserPolicy"]


def test_wildcard_question_mark_is_a_glob_not_a_regex():
    assert matches("iam:Cr?ateRole", "iam:CreateRole")
    assert not matches("iam:Cr?ateRole", "iam:CrrateRoleX")

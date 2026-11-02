"""Pass 2: the findings that only exist between statements.

A policy review that reads one statement at a time misses the thing that
actually matters. ``iam:CreateAccessKey`` on its own is a code smell;
``iam:CreateAccessKey`` in statement 1 and ``iam:AttachUserPolicy`` in
statement 3 is a full account takeover, and no single-statement rule can say
so. Neither statement is wrong in isolation - the *pair* is.

So this pass builds, per policy, the set of escalation primitives it grants
(see :data:`iamlint.wildcard.PRIMITIVES`) plus the set of compute actions that
consume a passed role, and then checks them against the published escalation
shapes. Each finding names both statements, because "statement 1 plus
statement 3" is the fix's starting point: break the pair, not the policy.

Cross-policy mode (``--bundle``) does the same over every policy handed to one
run, which is the honest model for a principal: what matters is the union of
what is attached to it, not each document separately.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import CAT_ESCALATION, Finding, Policy, Statement, make_finding
from .rules import RULES
from .wildcard import PASS_ROLE_CONSUMERS, covers, matches, primitive_for

# (rule, first primitive, second primitive, human shape)
PAIRS: tuple[tuple[str, str, str], ...] = (
    ("IAM030", "create_access_key", "attach_managed"),
    ("IAM030", "create_access_key", "put_inline"),
    ("IAM030", "create_access_key", "add_to_group"),
    ("IAM031", "create_role", "attach_managed"),
    ("IAM031", "create_role", "put_inline"),
    ("IAM031", "create_role", "update_trust"),
    ("IAM032", "create_policy_version", "set_default_version"),
    ("IAM036", "login_profile", "attach_managed"),
    ("IAM036", "login_profile", "put_inline"),
    ("IAM037", "delete_boundary", "attach_managed"),
    ("IAM037", "delete_boundary", "put_inline"),
)

ASSUME_PRIMITIVE = "update_trust"
ASSUME_ACTION = "sts:AssumeRole"


@dataclass
class Grant:
    """Where a capability came from - the policy and the statement index."""

    policy: str
    index: int
    action: str
    loc: object  # model.Loc


@dataclass
class Path:
    rule: str
    title: str
    severity: str
    first: Grant
    second: Grant
    detail: str


def _primitives(stmt: Statement) -> dict[str, str]:
    """primitive key -> the action string that supplied it."""
    out: dict[str, str] = {}
    if not stmt.allows():
        return out
    for action in stmt.actions:
        prim = primitive_for(action.raw)
        if prim is not None and prim.key not in out:
            out[prim.key] = action.raw
    return out


def _compute_actions(stmt: Statement) -> list[str]:
    if not stmt.allows():
        return []
    return [a.raw for a in stmt.actions if any(covers(a.raw, p) for p in PASS_ROLE_CONSUMERS)]


def _grants(policy: Policy) -> list[tuple[Statement, dict[str, str]]]:
    return [(s, _primitives(s)) for s in policy.statements]


def run_pass2(policy: Policy) -> list[Finding]:
    """Escalation shapes inside one policy document."""
    return _combine([policy], cross_policy=False)


def run_pass2_bundle(policies: list[Policy]) -> list[Finding]:
    """Escalation shapes across a set of policies attached to one principal."""
    return _combine(policies, cross_policy=True)


def _combine(policies: list[Policy], *, cross_policy: bool) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, frozenset]] = set()
    entries: list[tuple[Policy, Statement, dict[str, str]]] = []
    for policy in policies:
        if not policy.ok:
            continue
        for stmt, prims in _grants(policy):
            entries.append((policy, stmt, prims))

    for rule, first_key, second_key in PAIRS:
        for policy_a, stmt_a, prims_a in entries:
            if first_key not in prims_a:
                continue
            for policy_b, stmt_b, prims_b in entries:
                if second_key not in prims_b:
                    continue
                if not cross_policy:
                    if policy_a is not policy_b:
                        continue
                    if stmt_a.index == stmt_b.index:
                        continue
                elif policy_a is policy_b and stmt_a.index == stmt_b.index:
                    continue
                key = (rule, frozenset({(policy_a.path, stmt_a.index), (policy_b.path, stmt_b.index)}))
                if key in seen:
                    continue
                seen.add(key)
                meta = RULES[rule]
                out.append(
                    make_finding(
                        rule=rule,
                        title=meta.title,
                        severity=meta.severity,
                        category=CAT_ESCALATION,
                        file=policy_a.path,
                        loc=_action_loc(stmt_a, prims_a[first_key]),
                        saw=f"{prims_a[first_key]!r} (statement {stmt_a.index}) + "
                        f"{prims_b[second_key]!r} (statement {stmt_b.index}"
                        + (f" of {policy_b.path})" if cross_policy else ")"),
                        fix="Break the pair: keep one of "
                        f"{prims_a[first_key]!r} / {prims_b[second_key]!r}, scope it, or remove it.",
                        ref=meta.ref,
                        partner=f"{policy_b.path}:{_action_loc(stmt_b, prims_b[second_key]).render()}"
                        f" (statement {stmt_b.index})",
                        tags=[first_key, second_key],
                    )
                )

    out += _pass_role_paths(entries, cross_policy)
    out += _assume_paths(entries, cross_policy)
    return out


def _action_loc(stmt: Statement, action: str):
    for a in stmt.actions:
        if a.raw == action:
            return a.loc
    return stmt.loc


def _pass_role_paths(entries: list[tuple[Policy, Statement, dict[str, str]]], cross_policy: bool) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, frozenset]] = set()
    for policy_a, stmt_a, prims_a in entries:
        if "pass_role" not in prims_a:
            continue
        for policy_b, stmt_b, _prims_b in entries:
            if not cross_policy and policy_a is not policy_b:
                continue
            compute = _compute_actions(stmt_b)
            if not compute:
                continue
            if not cross_policy and stmt_a.index == stmt_b.index:
                continue
            if cross_policy and policy_a is policy_b and stmt_a.index == stmt_b.index:
                continue
            rule = "IAM033" if [c for c in compute if c.lower().startswith("lambda:")] else "IAM034"
            key = (rule, frozenset({(policy_a.path, stmt_a.index), (policy_b.path, stmt_b.index)}))
            if key in seen:
                continue
            seen.add(key)
            meta = RULES[rule]
            out.append(
                make_finding(
                    rule=rule,
                    title=meta.title,
                    severity=meta.severity,
                    category=CAT_ESCALATION,
                    file=policy_a.path,
                    loc=_action_loc(stmt_a, prims_a["pass_role"]),
                    saw=f"{prims_a['pass_role']!r} (statement {stmt_a.index}) + {compute[0]!r} "
                    f"(statement {stmt_b.index}" + (f" of {policy_b.path})" if cross_policy else ")"),
                    fix="Constrain iam:PassRole with iam:PassedToService, or scope the role ARN.",
                    ref=meta.ref,
                    partner=f"{policy_b.path}:{_action_loc(stmt_b, compute[0]).render()} (statement {stmt_b.index})",
                    tags=["pass_role"],
                )
            )
    return out


def _assume_paths(entries: list[tuple[Policy, Statement, dict[str, str]]], cross_policy: bool) -> list[Finding]:
    """update_trust + sts:AssumeRole: rewrite the trust, then walk through it."""
    out: list[Finding] = []
    seen: set[tuple[str, frozenset]] = set()
    for policy_a, stmt_a, prims_a in entries:
        if "update_trust" not in prims_a:
            continue
        for policy_b, stmt_b, _prims_b in entries:
            if not cross_policy and policy_a is not policy_b:
                continue
            if not stmt_b.allows():
                continue
            assume = [a.raw for a in stmt_b.actions if matches("sts:AssumeRole*", a.raw)]
            if not assume:
                continue
            if not cross_policy and stmt_a.index == stmt_b.index:
                continue
            key = ("IAM035", frozenset({(policy_a.path, stmt_a.index), (policy_b.path, stmt_b.index)}))
            if key in seen:
                continue
            seen.add(key)
            meta = RULES["IAM035"]
            out.append(
                make_finding(
                    rule="IAM035",
                    title=meta.title,
                    severity=meta.severity,
                    category=CAT_ESCALATION,
                    file=policy_a.path,
                    loc=_action_loc(stmt_a, prims_a["update_trust"]),
                    saw=f"{prims_a['update_trust']!r} (statement {stmt_a.index}) + {assume[0]!r} "
                    f"(statement {stmt_b.index}" + (f" of {policy_b.path})" if cross_policy else ")"),
                    fix="Separate trust management from the ability to assume; scope UpdateAssumeRolePolicy to one role.",
                    ref=meta.ref,
                    partner=f"{policy_b.path}:{_action_loc(stmt_b, assume[0]).render()} (statement {stmt_b.index})",
                    tags=["update_trust"],
                )
            )
    return out


def paths(policies: list[Policy]) -> list[Path]:
    """Structured form of pass 2, for the MCP tool and for tests."""
    out: list[Path] = []
    entries: list[tuple[Policy, Statement, dict[str, str]]] = []
    for policy in policies:
        if policy.ok:
            for stmt, prims in _grants(policy):
                entries.append((policy, stmt, prims))
    for rule, first_key, second_key in PAIRS:
        for policy_a, stmt_a, prims_a in entries:
            if first_key not in prims_a:
                continue
            for policy_b, stmt_b, prims_b in entries:
                if second_key not in prims_b or (policy_a is policy_b and stmt_a.index == stmt_b.index):
                    continue
                meta = RULES[rule]
                out.append(
                    Path(
                        rule=rule,
                        title=meta.title,
                        severity=meta.severity,
                        first=Grant(policy_a.path, stmt_a.index, prims_a[first_key], _action_loc(stmt_a, prims_a[first_key])),
                        second=Grant(policy_b.path, stmt_b.index, prims_b[second_key], _action_loc(stmt_b, prims_b[second_key])),
                        detail=f"{prims_a[first_key]} + {prims_b[second_key]}",
                    )
                )
    return out

"""Turn a located JSON tree into policy objects.

IAM accepts shapes the JSON schema people assume it does not:

* ``"Action": "s3:GetObject"`` - a bare string, not a list;
* ``"Statement": {...}`` - one statement, not a list of one;
* ``"Principal": "*"`` - the everyone principal, as a string;
* ``"Principal": {"AWS": ["arn:...", "123456789012"]}`` - a mix of ARNs,
  bare account ids and, occasionally, ``"*"``.

A parser that rejects those is a parser that cannot read production policies,
so every field is normalised to a list here. The normalisation is recorded
(``scalar_action``, ``scalar_resource``) because "you wrote a string where a
list belongs" is itself worth a low-severity note.
"""

from __future__ import annotations

from typing import Any

from .jsonloc import JsonError, Node, loads, pointer_escape, snippet
from .model import Action, Loc, Policy, Principal, Resource, Statement
from .wildcard import classify, split_action

EFFECT_ALLOW = "Allow"
EFFECT_DENY = "Deny"

PRINCIPAL_KINDS = ("AWS", "Service", "Federated", "CanonicalUser")

# AWS rejects a policy whose Statement/Version keys are missing, but a partial
# document still needs to parse so the report can say what is wrong with it.


def _loc(node: Node, text: str, path: str | None = None) -> Loc:
    return Loc(
        path=path if path is not None else node.path,
        line=node.line,
        col=node.col,
        snippet=snippet(text, node.line, node.col),
    )


def _as_list(node: Node | None) -> tuple[list[Node], bool]:
    """Normalise a field to a list of child nodes; ``scalar`` says it wasn't one."""
    if node is None:
        return [], False
    if node.is_array():
        return list(node.items), False
    return [node], True


def _strings(node: Node, text: str) -> list[Action]:
    out: list[Action] = []
    for child in node.items if node.is_array() else [node]:
        if not child.is_str():
            continue  # a non-string action is a type error the rules pass reports
        service, verb = split_action(child.value)
        out.append(
            Action(
                raw=child.value,
                loc=_loc(child, text),
                service=service,
                verb=verb,
                wildcard=classify(child.value),
            )
        )
    return out


def _resources(node: Node, text: str) -> list[Resource]:
    out: list[Resource] = []
    for child in node.items if node.is_array() else [node]:
        if not child.is_str():
            continue
        out.append(Resource(raw=child.value, loc=_loc(child, text)))
    return out


def _principals(node: Node, text: str) -> list[Principal]:
    out: list[Principal] = []
    if node.is_str():
        # "Principal": "*" - everyone. Also the shape people write by accident.
        out.append(Principal(kind="*", value=node.value, loc=_loc(node, text)))
        return out
    if not node.is_object():
        return out
    for child in node.items:
        kind = child.path.rsplit("/", 1)[-1]
        kind = kind.replace("~1", "/").replace("~0", "~")
        values: list[Node] = child.items if child.is_array() else [child]
        for value_node in values:
            if not value_node.is_str():
                continue
            out.append(Principal(kind=kind, value=value_node.value, loc=_loc(value_node, text)))
    return out


def _conditions(node: Node, text: str) -> tuple[dict[str, dict[str, list[Any]]], dict[str, Loc]]:
    """``{"StringEquals": {"aws:PrincipalOrgID": "o-123"}}`` -> normalised values."""
    out: dict[str, dict[str, list[Any]]] = {}
    locs: dict[str, Loc] = {}
    if not node.is_object():
        return out, locs
    for op_node in node.items:
        operator = op_node.path.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")
        locs[operator] = _loc(op_node, text)
        inner: dict[str, list[Any]] = {}
        if op_node.is_object():
            for key_node in op_node.items:
                key = key_node.path.rsplit("/", 1)[-1].replace("~1", "/").replace("~0", "~")
                if key_node.is_array():
                    inner[key] = [v.value for v in key_node.items]
                else:
                    inner[key] = [key_node.value]
        out[operator] = inner
    return out, locs


def parse_statement(node: Node, text: str, index: int) -> Statement:
    effect_node = node.get("Effect")
    raw_effect = effect_node.value if effect_node is not None and effect_node.is_str() else ""
    effect = raw_effect.strip().lower().capitalize() if raw_effect else ""

    action_node = node.get("Action")
    not_action_node = node.get("NotAction")
    resource_node = node.get("Resource")
    not_resource_node = node.get("NotResource")
    principal_node = node.get("Principal")
    not_principal_node = node.get("NotPrincipal")
    condition_node = node.get("Condition")
    sid_node = node.get("Sid")

    action_children, scalar_action = _as_list(action_node)
    resource_children, scalar_resource = _as_list(resource_node)

    conditions, condition_locs = _conditions(condition_node, text) if condition_node is not None else ({}, {})

    stmt = Statement(
        index=index,
        effect=effect,
        raw_effect=raw_effect,
        actions=_strings(action_node, text) if action_node is not None else [],
        not_actions=_strings(not_action_node, text) if not_action_node is not None else [],
        resources=_resources(resource_node, text) if resource_node is not None else [],
        not_resources=_resources(not_resource_node, text) if not_resource_node is not None else [],
        principals=_principals(principal_node, text) if principal_node is not None else [],
        not_principals=_principals(not_principal_node, text) if not_principal_node is not None else [],
        conditions=conditions,
        condition_locs=condition_locs,
        sid=sid_node.value if sid_node is not None and sid_node.is_str() else None,
        sid_loc=_loc(sid_node, text) if sid_node is not None else None,
        loc=_loc(node, text, f"{node.path}" or f"/Statement/{index}"),
        scalar_action=scalar_action and bool(action_children),
        scalar_resource=scalar_resource and bool(resource_children),
    )
    return stmt


def _classify_kind(statements: list[Statement]) -> str:
    has_principal = any(s.principals or s.not_principals for s in statements)
    if not has_principal:
        return "identity"
    # A trust policy has a Principal but no Resource; a resource-based policy
    # (S3 bucket, KMS key, SQS queue) has both.
    has_resource = any(s.resources or s.not_resources for s in statements)
    assume = any(a.raw.lower().startswith("sts:assumerole") for s in statements for a in s.actions)
    if has_resource and not assume:
        return "resource"
    if assume:
        return "trust"
    return "resource" if has_resource else "trust"


def parse_policy(text: str, path: str = "<text>") -> Policy:
    """Parse one policy document. Never raises for syntax: errors land on the Policy."""
    try:
        root = loads(text)
    except JsonError as exc:
        return Policy(
            path=path,
            text=text,
            root=None,
            statements=[],
            kind="unknown",
            parse_error=exc.message,
            error_line=exc.line,
            error_col=exc.col,
        )

    version_node = root.get("Version") if root.is_object() else None
    id_node = root.get("Id") if root.is_object() else None
    statement_node = root.get("Statement") if root.is_object() else None

    statements: list[Statement] = []
    if statement_node is not None:
        children = statement_node.items if statement_node.is_array() else [statement_node]
        for index, child in enumerate(children):
            if not child.is_object():
                continue
            statements.append(parse_statement(child, text, index))

    policy = Policy(
        path=path,
        text=text,
        root=root,
        statements=statements,
        version=version_node.value if version_node is not None and version_node.is_str() else None,
        version_loc=_loc(version_node, text) if version_node is not None else None,
        id=id_node.value if id_node is not None and id_node.is_str() else None,
        kind=_classify_kind(statements),
    )
    return policy


def parse_file(path: str) -> Policy:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    return parse_policy(text, path)


def statement_pointer(index: int) -> str:
    return f"/Statement/{index}"


def field_pointer(index: int, field: str) -> str:
    return f"/Statement/{index}/{pointer_escape(field)}"

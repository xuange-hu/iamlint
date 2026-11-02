"""Pass 1: everything that can be decided by reading one statement.

Pass 2 (:mod:`iamlint.graph`) looks at combinations. The split is deliberate: a
single statement can be dangerous on its own, but the findings that get people
fired are the ones where two harmless-looking statements add up. Keeping them
apart keeps the report honest - a graph finding names both statements.

Every rule below is registered in :data:`RULES`, which is what
``iamlint rules``, the MCP ``explain_rule`` tool and the demo contract test all
read from, so adding a rule cannot silently skip the docs.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import (
    CAT_CONDITION,
    CAT_ESCALATION,
    CAT_HYGIENE,
    CAT_RESOURCE,
    CAT_TRUST,
    CAT_WILDCARD,
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    Finding,
    Loc,
    Policy,
    Statement,
    make_finding,
)
from .wildcard import (
    PRIMITIVES,
    SENSITIVE_SERVICES,
    WILDCARD_FULL,
    WILDCARD_INNER,
    WILDCARD_PREFIX,
    arn_account,
    cidr_is_broad,
    covers,
    is_service_wide,
    is_write,
    matches,
    primitive_for,
    service_of,
)

AWS_IAM_REF = "AWS IAM best practices: grant least privilege"
ESCALATION_REF = "MITRE ATT&CK T1078.004 Valid Accounts: Cloud Accounts / AWS privesc primitives"
CONFUSED_DEPUTY_REF = "AWS confused-deputy problem: https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"
CONDITION_REF = "IAM condition keys: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html"
SIZE_REF = "IAM policy size limits: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    ref: str
    why: str = ""


RULES: dict[str, Rule] = {}


def _register(rule: Rule) -> Rule:
    RULES[rule.id] = rule
    return rule


def _r(rule_id: str, title: str, severity: str, category: str, ref: str, why: str = "") -> Rule:
    return _register(Rule(rule_id, title, severity, category, ref, why))


# --- wildcard ---------------------------------------------------------------
_r("IAM001", "Action is '*': the statement grants every action in AWS", CRITICAL, CAT_WILDCARD, AWS_IAM_REF,
   "A single '*' action makes every other control in the account irrelevant.")
_r("IAM002", "Service-wide wildcard action ('iam:*', 's3:*', ...)", HIGH, CAT_WILDCARD, AWS_IAM_REF,
   "Service-wide wildcards include the write and admin verbs you did not mean to grant.")
_r("IAM003", "Resource '*' with a write action", HIGH, CAT_WILDCARD, AWS_IAM_REF,
   "'*' on a write action means any resource in the account, including ones created later.")
_r("IAM004", "Principal '*': anyone, including anonymous, may use this", CRITICAL, CAT_WILDCARD, AWS_IAM_REF,
   "An unqualified principal is public access; it is the root cause of most bucket leaks.")
_r("IAM005", "NotAction with Allow: an inverted allow-list", HIGH, CAT_WILDCARD, AWS_IAM_REF,
   "NotAction grants every action except the ones listed, including future ones.")
_r("IAM006", "NotResource with Allow: an inverted resource list", HIGH, CAT_WILDCARD, AWS_IAM_REF,
   "NotResource applies to every resource except the ones listed.")
_r("IAM007", "Wildcard inside the action verb ('iam:Create*')", MEDIUM, CAT_WILDCARD, AWS_IAM_REF,
   "A mid-string wildcard silently grows whenever AWS ships a new verb.")
_r("IAM008", "sts:AssumeRole against Resource '*'", HIGH, CAT_WILDCARD, AWS_IAM_REF,
   "Assume-any-role is one step from admin in most accounts.")

# --- escalation primitives --------------------------------------------------
_PRIMITIVE_SEVERITY = {
    "create_access_key": HIGH,
    "login_profile": HIGH,
    "attach_managed": HIGH,
    "put_inline": HIGH,
    "update_trust": HIGH,
    "pass_role": HIGH,
    "add_to_group": MEDIUM,
    "create_policy_version": MEDIUM,
    "set_default_version": MEDIUM,
    "create_role": MEDIUM,
    "delete_boundary": MEDIUM,
}
for _prim in PRIMITIVES:
    _r(_prim.rule, f"Privilege-escalation primitive: {_prim.title}", _PRIMITIVE_SEVERITY[_prim.key], CAT_ESCALATION,
       ESCALATION_REF, _prim.why)

# --- graph (pass 2) ---------------------------------------------------------
_r("IAM030", "Credential minting plus policy write: full escalation chain", CRITICAL, CAT_ESCALATION, ESCALATION_REF,
   "Create another identity's key, then attach it admin: the account is gone.")
_r("IAM031", "Role creation plus policy write: backdoor role", CRITICAL, CAT_ESCALATION, ESCALATION_REF,
   "Create a role you can assume and give it whatever you want.")
_r("IAM032", "Policy version write plus set-default: policy hijack", CRITICAL, CAT_ESCALATION, ESCALATION_REF,
   "Create a permissive version, then make it the default - the audit trail shows a version bump.")
_r("IAM033", "PassRole plus Lambda code write: code execution on a role", CRITICAL, CAT_ESCALATION, ESCALATION_REF,
   "A Lambda you control running as a privileged role is remote code execution.")
_r("IAM034", "PassRole plus a compute service that runs code", HIGH, CAT_ESCALATION, ESCALATION_REF,
   "EC2/ECS/Glue/CloudFormation with PassRole hands your code the role's credentials.")
_r("IAM035", "Trust rewrite plus AssumeRole: assume anything", CRITICAL, CAT_ESCALATION, ESCALATION_REF,
   "Rewrite who may assume a role, then assume it.")
_r("IAM036", "Password reset plus policy write: console takeover", HIGH, CAT_ESCALATION, ESCALATION_REF,
   "Console access plus a policy write means persistent, visible-as-legitimate admin.")
_r("IAM037", "Boundary removal plus policy write: escape the boundary", HIGH, CAT_ESCALATION, ESCALATION_REF,
   "Permissions boundaries are the last line; removing one then writing policy defeats it.")

# --- trust policy -----------------------------------------------------------
_r("IAM040", "Trust policy trusts everyone ('Principal': '*')", CRITICAL, CAT_TRUST, AWS_IAM_REF,
   "Anyone with an AWS account can assume this role.")
_r("IAM041", "Cross-account trust without an ExternalId", HIGH, CAT_TRUST, CONFUSED_DEPUTY_REF,
   "Without ExternalId a third party can be tricked into using your role.")
_r("IAM042", "Trust principal contains a wildcard account or role", HIGH, CAT_TRUST, AWS_IAM_REF,
   "'arn:aws:iam::*:role/x' matches roles in accounts you do not control.")
_r("IAM043", "sts:AssumeRole with no Condition at all", MEDIUM, CAT_TRUST, AWS_IAM_REF,
   "No condition means no MFA, no source-IP and no org restriction on a privileged handoff.")
_r("IAM044", "Wildcard service principal in a trust policy", MEDIUM, CAT_TRUST, CONFUSED_DEPUTY_REF,
   "'*.amazonaws.com' lets any AWS service be the caller.")
_r("IAM045", "Federated trust without a subject condition", MEDIUM, CAT_TRUST, CONFUSED_DEPUTY_REF,
   "An OIDC/SAML trust with no sub/aud check accepts tokens from the wrong tenant.")

# --- conditions -------------------------------------------------------------
_r("IAM050", "Condition on a source IP with a very broad CIDR", HIGH, CAT_CONDITION, CONDITION_REF,
   "A /0 or /8 IP condition is documentation, not a control.")
_r("IAM051", "Condition value contains a wildcard", MEDIUM, CAT_CONDITION, CONDITION_REF,
   "StringLike with '*' matches more than the value you had in mind.")
_r("IAM052", "Privileged action with no Condition at all", HIGH, CAT_CONDITION, CONDITION_REF,
   "Nothing narrows when or from where this may be used.")
_r("IAM053", "Condition requires MFA to be absent", MEDIUM, CAT_CONDITION, CONDITION_REF,
   '"MultiFactorAuthPresent": "false" flips MFA from a requirement into a hole.')
_r("IAM054", "Condition relies on a tag being absent (Null)", MEDIUM, CAT_CONDITION, CONDITION_REF,
   "A Null condition is satisfied by whoever can leave the tag off - usually the caller.")

# --- resources --------------------------------------------------------------
_r("IAM060", "Statement has no Resource", MEDIUM, CAT_RESOURCE, AWS_IAM_REF,
   "An identity-policy statement without Resource cannot be evaluated as intended.")
_r("IAM061", "Resource is not an ARN", MEDIUM, CAT_RESOURCE, AWS_IAM_REF,
   "A bare name does not identify a resource; the statement does not do what it looks like.")
_r("IAM062", "Resource '*' on a credential or secret service", HIGH, CAT_RESOURCE, AWS_IAM_REF,
   "'*' over KMS/Secrets Manager/SSM/IAM means every secret in the account.")
_r("IAM063", "Resource ARN with a wildcard account id", MEDIUM, CAT_RESOURCE, AWS_IAM_REF,
   "A wildcard account in an ARN reaches into accounts you do not own.")
_r("IAM064", "Resource ARN with a wildcard region", LOW, CAT_RESOURCE, AWS_IAM_REF,
   "A region wildcard quietly covers every region you will ever enable.")

# --- hygiene ----------------------------------------------------------------
_r("IAM070", "Missing or outdated policy Version", LOW, CAT_HYGIENE, AWS_IAM_REF,
   "Without '2012-10-17' policy variables and some condition keys do not evaluate.")
_r("IAM071", "Statement has no Sid", LOW, CAT_HYGIENE, AWS_IAM_REF,
   "A Sid is how a reviewer, a ticket and a future you refer to the same statement.")
_r("IAM072", "Duplicate Sid inside one policy", LOW, CAT_HYGIENE, AWS_IAM_REF,
   "Two statements with one Sid make every reference to it ambiguous.")
_r("IAM073", "Duplicate JSON key: the later one silently wins", MEDIUM, CAT_HYGIENE, AWS_IAM_REF,
   "JSON keeps the last value; a reviewer reading the file sees the first.")
_r("IAM074", "Policy does not parse", HIGH, CAT_HYGIENE, AWS_IAM_REF,
   "A policy AWS rejects is a policy nobody reviews - and the failure is silent in IaC diffs.")
_r("IAM075", "Policy is at or near the AWS size limit", LOW, CAT_HYGIENE, SIZE_REF,
   "Policies near the quota get split ad hoc, which is how gaps appear.")

SIZE_LIMIT_IDENTITY = 6144
SIZE_LIMIT_RESOURCE = 10240


def rule_ids() -> list[str]:
    return sorted(RULES)


def rule(id_: str) -> Rule | None:
    return RULES.get(id_.upper())


# ---------------------------------------------------------------------------
# pass 1
# ---------------------------------------------------------------------------


def _saw(field: str, values: list[str]) -> str:
    shown = ", ".join(repr(v) for v in values[:4])
    if len(values) > 4:
        shown += f", ... (+{len(values) - 4} more)"
    return f'{field} = [{shown}]' if len(values) != 1 else f"{field} = {values[0]!r}"


def _loc_of(values: list, fallback: Loc) -> Loc:
    return values[0].loc if values else fallback


def run_pass1(policy: Policy) -> list[Finding]:
    """All single-statement rules. Parse errors are handled by the caller."""
    out: list[Finding] = []
    for stmt in policy.statements:
        out += _wildcard_rules(policy, stmt)
        out += _escalation_rules(policy, stmt)
        out += _trust_rules(policy, stmt)
        out += _condition_rules(policy, stmt)
        out += _resource_rules(policy, stmt)
    out += _hygiene_rules(policy)
    return out


def _wildcard_rules(policy: Policy, stmt: Statement) -> list[Finding]:
    out: list[Finding] = []
    file = policy.path
    allow = stmt.allows()

    for action in stmt.actions:
        if not allow:
            break
        if action.wildcard == WILDCARD_FULL:
            out.append(
                make_finding(
                    rule="IAM001",
                    title=RULES["IAM001"].title,
                    severity=RULES["IAM001"].severity,
                    category=CAT_WILDCARD,
                    file=file,
                    loc=action.loc,
                    saw=f"Effect = 'Allow', Action = {action.raw!r}",
                    fix="Enumerate the actions the workload actually calls.",
                    ref=AWS_IAM_REF,
                )
            )
        elif action.raw.endswith(":*") or action.raw == "*:*":
            out.append(
                make_finding(
                    rule="IAM002",
                    title=RULES["IAM002"].title,
                    severity=RULES["IAM002"].severity,
                    category=CAT_WILDCARD,
                    file=file,
                    loc=action.loc,
                    saw=f"Action = {action.raw!r} (Effect = 'Allow')",
                    fix=f"Replace {action.raw!r} with the specific {action.service} verbs in use.",
                    ref=AWS_IAM_REF,
                )
            )
        elif action.wildcard in (WILDCARD_INNER, WILDCARD_PREFIX) and action.raw != "*":
            out.append(
                make_finding(
                    rule="IAM007",
                    title=RULES["IAM007"].title,
                    severity=RULES["IAM007"].severity,
                    category=CAT_WILDCARD,
                    file=file,
                    loc=action.loc,
                    saw=f"Action = {action.raw!r}",
                    fix=f"List the {action.service} verbs behind the wildcard explicitly.",
                    ref=AWS_IAM_REF,
                )
            )

    if allow and stmt.resources:
        starred = [r for r in stmt.resources if r.raw == "*"]
        writes = [a.raw for a in stmt.actions if is_write(a.raw) and a.raw != "*"]
        if starred and writes:
            out.append(
                make_finding(
                    rule="IAM003",
                    title=RULES["IAM003"].title,
                    severity=RULES["IAM003"].severity,
                    category=CAT_WILDCARD,
                    file=file,
                    loc=starred[0].loc,
                    saw=f"Resource = '*' with {_saw('Action', writes)}",
                    fix="Scope the resource to the ARN(s) this workload touches.",
                    ref=AWS_IAM_REF,
                )
            )

    for principal in stmt.principals:
        if not allow:
            break
        if principal.value == "*" or principal.kind == "*":
            out.append(
                make_finding(
                    rule="IAM004",
                    title=RULES["IAM004"].title,
                    severity=RULES["IAM004"].severity,
                    category=CAT_WILDCARD,
                    file=file,
                    loc=principal.loc,
                    saw=f"Principal = {principal.value!r} (Effect = 'Allow')",
                    fix="Name the account, role or service that is supposed to call this.",
                    ref=AWS_IAM_REF,
                )
            )

    if allow and stmt.not_actions:
        out.append(
            make_finding(
                rule="IAM005",
                title=RULES["IAM005"].title,
                severity=RULES["IAM005"].severity,
                category=CAT_WILDCARD,
                file=file,
                loc=stmt.not_actions[0].loc,
                saw=f"Effect = 'Allow', NotAction = {[a.raw for a in stmt.not_actions]}",
                fix="Invert to Action with an explicit allow-list.",
                ref=AWS_IAM_REF,
            )
        )
    if allow and stmt.not_resources:
        out.append(
            make_finding(
                rule="IAM006",
                title=RULES["IAM006"].title,
                severity=RULES["IAM006"].severity,
                category=CAT_WILDCARD,
                file=file,
                loc=stmt.not_resources[0].loc,
                saw=f"Effect = 'Allow', NotResource = {[r.raw for r in stmt.not_resources]}",
                fix="Invert to Resource with an explicit list.",
                ref=AWS_IAM_REF,
            )
        )

    for action in stmt.actions:
        # A blanket '*' already produced IAM001; naming AssumeRole on top of it
        # adds a line without adding information.
        assume_role = covers(action.raw, "sts:AssumeRole*")
        if allow and assume_role and not is_service_wide(action.raw) and any(r.raw == "*" for r in stmt.resources):
                out.append(
                    make_finding(
                        rule="IAM008",
                        title=RULES["IAM008"].title,
                        severity=RULES["IAM008"].severity,
                        category=CAT_WILDCARD,
                        file=file,
                        loc=action.loc,
                        saw=f"Action = {action.raw!r}, Resource = '*'",
                        fix="Name the role ARNs that may be assumed.",
                        ref=AWS_IAM_REF,
                    )
                )
    return out


def _escalation_rules(policy: Policy, stmt: Statement) -> list[Finding]:
    out: list[Finding] = []
    if not stmt.allows():
        return out
    seen: set[str] = set()
    for action in stmt.actions:
        prim = primitive_for(action.raw)
        if prim is None or prim.key in seen:
            continue
        seen.add(prim.key)
        meta = RULES[prim.rule]
        wild_resource = any(r.raw == "*" or "*" in r.raw for r in stmt.resources)
        severity = meta.severity
        saw = f"Action = {action.raw!r}"
        if stmt.resources:
            saw += f", Resource = {[r.raw for r in stmt.resources]}"
        if wild_resource:
            # Wildcard resource on a primitive is what turns "has the primitive"
            # into "has the primitive everywhere".
            severity = HIGH
            saw += " (wildcard resource)"
        out.append(
            make_finding(
                rule=prim.rule,
                title=meta.title,
                severity=severity,
                category=CAT_ESCALATION,
                file=policy.path,
                loc=action.loc,
                saw=saw,
                fix=f"Scope {action.raw!r} to the exact principal/resource ARN, or drop it.",
                ref=meta.ref,
                tags=[prim.key],
            )
        )
    return out


def _trust_rules(policy: Policy, stmt: Statement) -> list[Finding]:
    out: list[Finding] = []
    if not stmt.allows() or not stmt.principals:
        return out
    file = policy.path

    anyone = [p for p in stmt.principals if p.value == "*" or p.kind == "*"]
    if anyone:
        out.append(
            make_finding(
                rule="IAM040",
                title=RULES["IAM040"].title,
                severity=RULES["IAM040"].severity,
                category=CAT_TRUST,
                file=file,
                loc=anyone[0].loc,
                saw=f"Principal = {anyone[0].value!r}",
                fix="Trust a specific account/role ARN instead of '*'.",
                ref=AWS_IAM_REF,
            )
        )

    assume = any(matches("sts:AssumeRole", a.raw) for a in stmt.actions)
    condition_keys = {k for op in stmt.conditions for k in stmt.conditions[op]}
    own_account = _own_account(policy)

    for principal in stmt.principals:
        value = principal.value
        if principal.kind == "Service" and "*" in value:
            out.append(
                make_finding(
                    rule="IAM044",
                    title=RULES["IAM044"].title,
                    severity=RULES["IAM044"].severity,
                    category=CAT_TRUST,
                    file=file,
                    loc=principal.loc,
                    saw=f"Principal.Service = {value!r}",
                    fix="Name the exact service principal.",
                    ref=CONFUSED_DEPUTY_REF,
                )
            )
            continue
        if principal.kind == "Federated":
            pinned = any(k in {"sub", "aud"} or k.endswith((":sub", ":aud")) for k in condition_keys)
            if not pinned:
                out.append(
                    make_finding(
                        rule="IAM045",
                        title=RULES["IAM045"].title,
                        severity=RULES["IAM045"].severity,
                        category=CAT_TRUST,
                        file=file,
                        loc=principal.loc,
                        saw=f"Principal.Federated = {value!r}, Condition keys = {sorted(condition_keys) or 'none'}",
                        fix="Add StringEquals on '<provider>:sub' (and ':aud') so only your tenant matches.",
                        ref=CONFUSED_DEPUTY_REF,
                    )
                )
            continue
        if principal.kind != "AWS":
            continue
        if "*" in value and value != "*":
            out.append(
                make_finding(
                    rule="IAM042",
                    title=RULES["IAM042"].title,
                    severity=RULES["IAM042"].severity,
                    category=CAT_TRUST,
                    file=file,
                    loc=principal.loc,
                    saw=f"Principal.AWS = {value!r}",
                    fix="Write the full account/role ARN with no wildcard section.",
                    ref=AWS_IAM_REF,
                )
            )
            continue
        # "Cross-account" is decided against the account this policy itself lives
        # in, which we derive from the ARNs in the document rather than guessing.
        # With no ARN to compare against, any concrete principal is treated as
        # external: a false positive here costs one line, a false negative costs
        # the confused-deputy finding.
        principal_account = arn_account(value) if value.startswith("arn:") else (value if value.isdigit() else "")
        is_external = bool(principal_account) and (own_account is None or principal_account != own_account)
        if assume and is_external and "sts:ExternalId" not in condition_keys:
            out.append(
                make_finding(
                    rule="IAM041",
                    title=RULES["IAM041"].title,
                    severity=RULES["IAM041"].severity,
                    category=CAT_TRUST,
                    file=file,
                    loc=principal.loc,
                    saw=f"Principal.AWS = {value!r}, Condition keys = {sorted(condition_keys) or 'none'}",
                    fix='Add Condition StringEquals {"sts:ExternalId": "<per-partner id>"}.',
                    ref=CONFUSED_DEPUTY_REF,
                )
            )

    if assume and not stmt.conditions:
        out.append(
            make_finding(
                rule="IAM043",
                title=RULES["IAM043"].title,
                severity=RULES["IAM043"].severity,
                category=CAT_TRUST,
                file=file,
                loc=stmt.loc,
                saw="sts:AssumeRole with no Condition block",
                fix="Add at least an MFA or aws:PrincipalOrgID condition.",
                ref=AWS_IAM_REF,
            )
        )
    return out


def _own_account(policy: Policy) -> str | None:
    """The account this policy belongs to, taken from the ARNs inside it.

    A trust policy usually mentions its own role ARN in Resource or in the
    Sid-adjacent fields; using that as the baseline is what keeps IAM041 from
    firing on a same-account role hand-off.
    """
    counts: dict[str, int] = {}
    for stmt in policy.statements:
        for resource in stmt.resources:
            account = arn_account(resource.raw)
            if account and account.isdigit():
                counts[account] = counts.get(account, 0) + 1
    if not counts:
        return None
    return max(counts, key=lambda k: counts[k])


def _condition_rules(policy: Policy, stmt: Statement) -> list[Finding]:
    out: list[Finding] = []
    if not stmt.allows():
        return out
    file = policy.path

    for operator, keys in stmt.conditions.items():
        loc = stmt.condition_locs.get(operator, stmt.loc)
        for key, values in keys.items():
            if key.lower() in ("aws:sourceip", "aws:sourcevpce") and any(cidr_is_broad(str(v)) for v in values):
                out.append(
                    make_finding(
                        rule="IAM050",
                        title=RULES["IAM050"].title,
                        severity=RULES["IAM050"].severity,
                        category=CAT_CONDITION,
                        file=file,
                        loc=loc,
                        saw=f'Condition {operator} {key} = {values}',
                        fix="Narrow the CIDR to the addresses that actually need access.",
                        ref=CONDITION_REF,
                    )
                )
            if any("*" in str(v) or "?" in str(v) for v in values):
                out.append(
                    make_finding(
                        rule="IAM051",
                        title=RULES["IAM051"].title,
                        severity=RULES["IAM051"].severity,
                        category=CAT_CONDITION,
                        file=file,
                        loc=loc,
                        saw=f"Condition {operator} {key} = {values}",
                        fix="Use StringEquals with the exact value.",
                        ref=CONDITION_REF,
                    )
                )
            if key.lower() == "aws:multifactorauthpresent" and any(str(v).lower() == "false" for v in values):
                out.append(
                    make_finding(
                        rule="IAM053",
                        title=RULES["IAM053"].title,
                        severity=RULES["IAM053"].severity,
                        category=CAT_CONDITION,
                        file=file,
                        loc=loc,
                        saw=f"Condition {operator} {key} = {values}",
                        fix='Require MFA: Bool {"aws:MultiFactorAuthPresent": "true"}.',
                        ref=CONDITION_REF,
                    )
                )
            if operator.lower() == "null":
                out.append(
                    make_finding(
                        rule="IAM054",
                        title=RULES["IAM054"].title,
                        severity=RULES["IAM054"].severity,
                        category=CAT_CONDITION,
                        file=file,
                        loc=loc,
                        saw=f"Condition Null {key} = {values}",
                        fix="Assert the expected value instead of the absence of a tag.",
                        ref=CONDITION_REF,
                    )
                )

    privileged = [
        a for a in stmt.actions if primitive_for(a.raw) or (service_of(a.raw) in SENSITIVE_SERVICES and is_write(a.raw))
    ]
    if privileged and not stmt.conditions:
        out.append(
            make_finding(
                rule="IAM052",
                title=RULES["IAM052"].title,
                severity=RULES["IAM052"].severity,
                category=CAT_CONDITION,
                file=file,
                loc=privileged[0].loc,
                saw=f"{_saw('Action', [a.raw for a in privileged])} with no Condition",
                fix="Add a condition that narrows who/where/when (org, source IP, MFA).",
                ref=CONDITION_REF,
            )
        )
    return out


def _resource_rules(policy: Policy, stmt: Statement) -> list[Finding]:
    out: list[Finding] = []
    if not stmt.allows():
        return out
    file = policy.path

    if policy.kind == "identity" and not stmt.resources and not stmt.not_resources:
        out.append(
            make_finding(
                rule="IAM060",
                title=RULES["IAM060"].title,
                severity=RULES["IAM060"].severity,
                category=CAT_RESOURCE,
                file=file,
                loc=stmt.loc,
                saw=f"Statement {stmt.index} has Action but no Resource",
                fix="Add an explicit Resource list.",
                ref=AWS_IAM_REF,
            )
        )

    for resource in stmt.resources:
        raw = resource.raw
        if raw == "*":
            sensitive = [a for a in stmt.actions if service_of(a.raw) in SENSITIVE_SERVICES]
            # A write on '*' already produced IAM003. This rule owns the other
            # half of the problem: reading every secret in the account is a
            # breach without anybody writing anything.
            writes = [a for a in stmt.actions if is_write(a.raw) and a.raw != "*"]
            if sensitive and not writes:
                out.append(
                    make_finding(
                        rule="IAM062",
                        title=RULES["IAM062"].title,
                        severity=RULES["IAM062"].severity,
                        category=CAT_RESOURCE,
                        file=file,
                        loc=resource.loc,
                        saw=f"Resource = '*' with {_saw('Action', [a.raw for a in sensitive])}",
                        fix="Scope to the specific key/secret/parameter ARNs.",
                        ref=AWS_IAM_REF,
                    )
                )
            continue
        if not raw.startswith("arn:"):
            if raw.startswith("*"):
                continue  # a bare glob is IAM003's job
            out.append(
                make_finding(
                    rule="IAM061",
                    title=RULES["IAM061"].title,
                    severity=RULES["IAM061"].severity,
                    category=CAT_RESOURCE,
                    file=file,
                    loc=resource.loc,
                    saw=f"Resource = {raw!r}",
                    fix="Use the full ARN (arn:aws:<service>:<region>:<account>:<resource>).",
                    ref=AWS_IAM_REF,
                )
            )
            continue
        if arn_account(raw) == "*":
            out.append(
                make_finding(
                    rule="IAM063",
                    title=RULES["IAM063"].title,
                    severity=RULES["IAM063"].severity,
                    category=CAT_RESOURCE,
                    file=file,
                    loc=resource.loc,
                    saw=f"Resource = {raw!r} (account is '*')",
                    fix="Put your account id in the ARN.",
                    ref=AWS_IAM_REF,
                )
            )
        parts = raw.split(":", 5)
        if len(parts) > 3 and parts[3] == "*":
            out.append(
                make_finding(
                    rule="IAM064",
                    title=RULES["IAM064"].title,
                    severity=RULES["IAM064"].severity,
                    category=CAT_RESOURCE,
                    file=file,
                    loc=resource.loc,
                    saw=f"Resource = {raw!r} (region is '*')",
                    fix="Pin the region, or enumerate the regions you use.",
                    ref=AWS_IAM_REF,
                )
            )
    return out


def _hygiene_rules(policy: Policy) -> list[Finding]:
    out: list[Finding] = []
    file = policy.path

    if policy.version is None:
        out.append(
            make_finding(
                rule="IAM070",
                title=RULES["IAM070"].title,
                severity=RULES["IAM070"].severity,
                category=CAT_HYGIENE,
                file=file,
                loc=Loc(path="", line=1, col=1, snippet=(policy.text.splitlines() or [""])[0][:96]),
                saw="no Version field",
                fix='Add "Version": "2012-10-17".',
                ref=AWS_IAM_REF,
            )
        )
    elif policy.version != "2012-10-17" and policy.version_loc is not None:
        out.append(
            make_finding(
                rule="IAM070",
                title=RULES["IAM070"].title,
                severity=RULES["IAM070"].severity,
                category=CAT_HYGIENE,
                file=file,
                loc=policy.version_loc,
                saw=f"Version = {policy.version!r}",
                fix='Use "2012-10-17".',
                ref=AWS_IAM_REF,
            )
        )

    seen_sids: dict[str, Loc] = {}
    for stmt in policy.statements:
        if stmt.sid is None:
            out.append(
                make_finding(
                    rule="IAM071",
                    title=RULES["IAM071"].title,
                    severity=RULES["IAM071"].severity,
                    category=CAT_HYGIENE,
                    file=file,
                    loc=stmt.loc,
                    saw=f"Statement {stmt.index} has no Sid",
                    fix="Give each statement a stable, meaningful Sid.",
                    ref=AWS_IAM_REF,
                )
            )
        elif stmt.sid in seen_sids and stmt.sid_loc is not None:
            out.append(
                make_finding(
                    rule="IAM072",
                    title=RULES["IAM072"].title,
                    severity=RULES["IAM072"].severity,
                    category=CAT_HYGIENE,
                    file=file,
                    loc=stmt.sid_loc,
                    saw=f"Sid = {stmt.sid!r} (already used in statement {seen_sids[stmt.sid].path})",
                    fix="Sids must be unique within a policy.",
                    ref=AWS_IAM_REF,
                )
            )
        else:
            seen_sids[stmt.sid] = stmt.sid_loc or stmt.loc

    for name, line, col in _duplicate_keys(policy):
        out.append(
            make_finding(
                rule="IAM073",
                title=RULES["IAM073"].title,
                severity=RULES["IAM073"].severity,
                category=CAT_HYGIENE,
                file=file,
                loc=_dup_key_loc(policy, line, col),
                saw=f"duplicate key {name!r}",
                fix="Merge the two occurrences; the second one is the one AWS kept.",
                ref=AWS_IAM_REF,
            )
        )

    limit = SIZE_LIMIT_RESOURCE if policy.kind in ("resource", "trust") else SIZE_LIMIT_IDENTITY
    size = policy.size()
    if size > limit:
        out.append(
            make_finding(
                rule="IAM075",
                title=RULES["IAM075"].title,
                severity=RULES["IAM075"].severity,
                category=CAT_HYGIENE,
                file=file,
                loc=Loc(path="", line=1, col=1),
                saw=f"policy is {size} characters (AWS limit {limit})",
                fix="Split into several smaller policies attached by purpose.",
                ref=SIZE_REF,
            )
        )
    elif size > limit * 0.9:
        out.append(
            make_finding(
                rule="IAM075",
                title=RULES["IAM075"].title,
                severity=RULES["IAM075"].severity,
                category=CAT_HYGIENE,
                file=file,
                loc=Loc(path="", line=1, col=1),
                saw=f"policy is {size} characters ({100 * size // limit}% of the {limit} limit)",
                fix="Plan the split before you hit the quota mid-incident.",
                ref=SIZE_REF,
            )
        )
    return out


def _dup_key_loc(policy: Policy, line: int, col: int) -> Loc:
    """The line a duplicate key sits on, if the document still has that line."""
    lines = policy.text.splitlines()
    snippet_text = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
    return Loc(path="", line=line, col=col, snippet=snippet_text)


def _duplicate_keys(policy: Policy) -> list[tuple[str, int, int]]:
    """Depth-first sweep for objects with repeated keys."""
    out: list[tuple[str, int, int]] = []
    root = policy.root
    if root is None:
        return out
    stack = [root]
    while stack:
        node = stack.pop()
        if getattr(node, "dupes", None):
            out.extend(node.dupes)
        for child in getattr(node, "items", []):
            stack.append(child)
    return out

"""Data model: what a policy is, and what a finding says about it.

Every finding in this project is evidence-shaped. A reviewer should be able to
read a finding and re-derive it from the file without trusting us, so each one
carries four things and nothing else:

    where  - file:line:col plus the JSON Pointer into the policy
    saw    - the exact text at that address
    fix    - the smallest change that removes the finding
    ref    - why it matters (AWS doc / CIS / MITRE ATT&CK)

Anything that cannot be expressed that way is not a finding, it is an opinion,
and opinions belong in the docs, not in the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITIES = (CRITICAL, HIGH, MEDIUM, LOW, INFO)
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}

# Categories double as the CLI's --only/--skip vocabulary.
CAT_WILDCARD = "wildcard"
CAT_ESCALATION = "escalation"
CAT_GRAPH = "graph"
CAT_TRUST = "trust"
CAT_CONDITION = "condition"
CAT_RESOURCE = "resource"
CAT_HYGIENE = "hygiene"

CATEGORIES = (
    CAT_WILDCARD,
    CAT_ESCALATION,
    CAT_GRAPH,
    CAT_TRUST,
    CAT_CONDITION,
    CAT_RESOURCE,
    CAT_HYGIENE,
)


@dataclass
class Loc:
    """An address inside a policy file."""

    path: str = ""  # JSON Pointer, e.g. /Statement/0/Action/1
    line: int = 1
    col: int = 1
    snippet: str = ""

    def render(self) -> str:
        return f"{self.line}:{self.col}"


@dataclass
class Action:
    raw: str
    loc: Loc
    service: str = ""
    verb: str = ""
    wildcard: str = "none"  # none | full | prefix | suffix | inner

    @property
    def lower(self) -> str:
        return self.raw.lower()


@dataclass
class Resource:
    raw: str
    loc: Loc


@dataclass
class Principal:
    kind: str  # AWS | Service | Federated | CanonicalUser | "*"
    value: str
    loc: Loc


@dataclass
class Statement:
    index: int
    effect: str  # Allow | Deny, case-normalised
    raw_effect: str
    actions: list[Action] = field(default_factory=list)
    not_actions: list[Action] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    not_resources: list[Resource] = field(default_factory=list)
    principals: list[Principal] = field(default_factory=list)
    not_principals: list[Principal] = field(default_factory=list)
    conditions: dict[str, dict[str, list[Any]]] = field(default_factory=dict)
    condition_locs: dict[str, Loc] = field(default_factory=dict)
    sid: str | None = None
    sid_loc: Loc | None = None
    loc: Loc = field(default_factory=Loc)
    # Set when Action/Resource/Principal arrived as a bare string instead of a list.
    scalar_action: bool = False
    scalar_resource: bool = False

    def allows(self) -> bool:
        return self.effect.lower() == "allow"

    def action_strings(self) -> list[str]:
        return [a.raw for a in self.actions]

    def resource_strings(self) -> list[str]:
        return [r.raw for r in self.resources]


@dataclass
class Policy:
    path: str  # file path, or "<stdin>" / "<text>"
    text: str
    root: Any  # jsonloc.Node
    statements: list[Statement]
    version: str | None = None
    version_loc: Loc | None = None
    id: str | None = None
    kind: str = "identity"  # identity | trust | resource | unknown
    parse_error: str | None = None
    error_line: int = 1
    error_col: int = 1

    @property
    def ok(self) -> bool:
        return self.parse_error is None

    def size(self) -> int:
        return len(self.text)


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    category: str
    where: str  # "path:line:col (/Statement/0/Action)"
    saw: str
    fix: str
    ref: str
    file: str = ""
    line: int = 1
    col: int = 1
    pointer: str = ""
    # Graph findings name the two statements they connect; single-statement ones
    # leave this empty, which is how the renderer knows to print one or two addresses.
    partner: str = ""
    tags: list[str] = field(default_factory=list)

    def sort_key(self) -> tuple[int, str, int, int]:
        return (SEVERITY_RANK.get(self.severity, 99), self.rule, self.line, self.col)


@dataclass
class Report:
    policies: list[Policy] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    suppressed: int = 0
    parse_errors: list[Finding] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out = dict.fromkeys(SEVERITIES, 0)
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def rules_fired(self) -> set[str]:
        return {f.rule for f in self.findings}

    def worst(self) -> str | None:
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key=lambda s: SEVERITY_RANK.get(s, 99))

    def grade(self) -> str:
        """A single letter, because a 40-line report needs a headline."""
        counts = self.counts()
        if counts[CRITICAL]:
            return "F"
        if counts[HIGH]:
            return "D"
        if counts[MEDIUM]:
            return "C"
        if counts[LOW]:
            return "B"
        return "A"


def make_finding(
    *,
    rule: str,
    title: str,
    severity: str,
    category: str,
    file: str,
    loc: Loc,
    saw: str,
    fix: str,
    ref: str,
    partner: str = "",
    tags: list[str] | None = None,
) -> Finding:
    return Finding(
        rule=rule,
        title=title,
        severity=severity,
        category=category,
        where=f"{file}:{loc.render()}" + (f" ({loc.path})" if loc.path else ""),
        saw=saw,
        fix=fix,
        ref=ref,
        file=file,
        line=loc.line,
        col=loc.col,
        pointer=loc.path,
        partner=partner,
        tags=list(tags or []),
    )

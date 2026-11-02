"""MCP server: the same engine, callable from Claude Code / Cursor / Cline.

The MCP extra is optional (``pip install "iamlint[mcp]"``); the module imports
nothing from the SDK at module scope so the zero-dependency core stays
importable without it. Tool names are given explicitly - ``@mcp.tool()`` would
register the wrapper function names, which are not the names an agent should
see.
"""

from __future__ import annotations

import asyncio
import json

from . import __version__
from .analyze import Options, analyze_paths, analyze_text
from .demo import run_demo
from .graph import paths as graph_paths
from .model import SEVERITIES, SEVERITY_RANK
from .parse import parse_policy
from .render import report_to_dict
from .rules import RULES, rule_ids

TOOLS = (
    "iamlint_scan_text",
    "iamlint_scan_path",
    "iamlint_privilege_paths",
    "iamlint_rules",
    "iamlint_explain",
    "iamlint_demo",
)


def _options(min_severity: str = "info", categories: str = "", graph: bool = True, bundle: bool = False) -> Options:
    return Options(
        min_severity=min_severity if min_severity in SEVERITIES else "info",
        only={c.strip() for c in categories.split(",") if c.strip()},
        graph=graph,
        bundle=bundle,
    )


def scan_text(text: str, *, min_severity: str = "info", name: str = "<text>") -> dict:
    """Analyse a policy document given as text."""
    report = analyze_text(text, name, _options(min_severity))
    return report_to_dict(report)


def scan_path(path: str, *, min_severity: str = "info", bundle: bool = False) -> dict:
    """Analyse a file or a directory of policies."""
    report = analyze_paths([path], _options(min_severity, bundle=bundle))
    return report_to_dict(report)


def privilege_paths(text: str) -> dict:
    """Only the pass-2 combinations: what the statements add up to."""
    policy = parse_policy(text, "<text>")
    found = graph_paths([policy])
    return {
        "paths": [
            {
                "rule": p.rule,
                "title": p.title,
                "severity": p.severity,
                "first": {"statement": p.first.index, "action": p.first.action, "where": p.first.loc.render()},
                "second": {"statement": p.second.index, "action": p.second.action, "where": p.second.loc.render()},
                "detail": p.detail,
            }
            for p in found
        ]
    }


def list_rules(category: str = "") -> dict:
    rows = []
    for rid in rule_ids():
        meta = RULES[rid]
        if category and meta.category != category:
            continue
        rows.append({"id": rid, "severity": meta.severity, "category": meta.category, "title": meta.title})
    return {"rules": rows, "count": len(rows)}


def explain(rule_id: str) -> dict:
    meta = RULES.get(rule_id.upper())
    if meta is None:
        return {"error": f"unknown rule {rule_id}", "known": rule_ids()}
    return {
        "id": meta.id,
        "title": meta.title,
        "severity": meta.severity,
        "category": meta.category,
        "why": meta.why,
        "ref": meta.ref,
    }


def demo() -> dict:
    report = run_demo()
    data = report_to_dict(report)
    data["summary"] = {
        "rules_total": len(RULES),
        "rules_fired": len(report.rules_fired()),
        "findings": len(report.findings),
        "grade": report.grade(),
    }
    return data


def tool_manifest() -> list[dict]:
    """Names and descriptions, so a client can list them without the SDK."""
    return [
        {"name": "iamlint_scan_text", "description": "Audit an IAM policy document supplied as text."},
        {"name": "iamlint_scan_path", "description": "Audit an IAM policy file or a directory of policies."},
        {"name": "iamlint_privilege_paths", "description": "List the escalation combinations between statements."},
        {"name": "iamlint_rules", "description": "List the rule catalogue, optionally filtered by category."},
        {"name": "iamlint_explain", "description": "Explain one rule id: why it exists and what to do."},
        {"name": "iamlint_demo", "description": "Run the built-in demo set (no network, no AWS account)."},
    ]


def build_server():
    """Build the MCP server. Imports the SDK here, on purpose."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("iamlint")

    @mcp.tool(name="iamlint_scan_text")
    def _scan_text(text: str, min_severity: str = "info") -> str:
        return json.dumps(scan_text(text, min_severity=min_severity))

    @mcp.tool(name="iamlint_scan_path")
    def _scan_path(path: str, min_severity: str = "info", bundle: bool = False) -> str:
        return json.dumps(scan_path(path, min_severity=min_severity, bundle=bundle))

    @mcp.tool(name="iamlint_privilege_paths")
    def _privilege_paths(text: str) -> str:
        return json.dumps(privilege_paths(text))

    @mcp.tool(name="iamlint_rules")
    def _rules(category: str = "") -> str:
        return json.dumps(list_rules(category))

    @mcp.tool(name="iamlint_explain")
    def _explain(rule_id: str) -> str:
        return json.dumps(explain(rule_id))

    @mcp.tool(name="iamlint_demo")
    def _demo() -> str:
        return json.dumps(demo())

    return mcp


def _sorted_findings(payload: dict) -> list[dict]:
    return sorted(payload["findings"], key=lambda f: SEVERITY_RANK.get(f["severity"], 99))


def _self_check() -> str:
    """Tiny end-to-end proof used by tests and by `python -m iamlint.mcp_server`."""
    payload = scan_text('{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}')
    lines = [f"iamlint {__version__} - {len(TOOLS)} MCP tools", f"demo grade: {demo()['grade']}"]
    for finding in _sorted_findings(payload)[:3]:
        lines.append(f"  {finding['rule']} {finding['severity']} {finding['title']}")
    return "\n".join(lines)


def main() -> None:
    print(_self_check())
    try:
        server = build_server()
    except ImportError:
        print("mcp is not installed; install it with: pip install \"iamlint[mcp]\"")
        return
    asyncio.run(server.run_stdio_async())


if __name__ == "__main__":
    main()

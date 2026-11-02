"""MCP surface: the agents call these, so the names and shapes are the contract.

``build_server`` needs the optional extra; everything else must work without it.
"""

from __future__ import annotations

import pytest
from helpers import doc, statement

import iamlint.mcp_server as mcp_mod
from iamlint.mcp_server import (
    TOOLS,
    demo,
    explain,
    list_rules,
    privilege_paths,
    scan_path,
    scan_text,
    tool_manifest,
)

POLICY = doc(statement(Sid="Admin", Action="*", Resource="*"))


def test_manifest_names_match_the_registration():
    assert [t["name"] for t in tool_manifest()] == list(TOOLS)


def test_every_tool_has_a_description():
    for tool in tool_manifest():
        assert tool["name"].startswith("iamlint_")
        assert tool["description"]


def test_scan_text_returns_findings_and_grade():
    payload = scan_text(POLICY)
    assert payload["grade"] == "F"
    assert "IAM001" in payload["rules_fired"]
    assert payload["findings"][0]["pointer"] == "/Statement/0/Action"


def test_scan_text_honours_min_severity():
    payload = scan_text(POLICY, min_severity="critical")
    assert {f["severity"] for f in payload["findings"]} == {"critical"}


def test_scan_path_reads_a_file(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(POLICY, encoding="utf-8")
    payload = scan_path(str(path))
    assert "IAM001" in payload["rules_fired"]


def test_privilege_paths_reports_the_pair():
    text = doc(
        statement(Sid="A", Action="iam:CreateAccessKey", Resource="*"),
        statement(Sid="B", Action="iam:AttachUserPolicy", Resource="*"),
    )
    payload = privilege_paths(text)
    assert payload["paths"]
    assert payload["paths"][0]["rule"] == "IAM030"
    assert payload["paths"][0]["first"]["statement"] != payload["paths"][0]["second"]["statement"]


def test_list_rules_can_filter():
    assert list_rules()["count"] == 49
    assert list_rules("trust")["count"] == 6
    assert all(r["category"] == "trust" for r in list_rules("trust")["rules"])


def test_explain_known_and_unknown():
    known = explain("IAM001")
    assert known["severity"] == "critical"
    assert known["why"]
    unknown = explain("IAM999")
    assert "error" in unknown


def test_explain_is_case_insensitive():
    assert explain("iam040")["id"] == "IAM040"


def test_demo_payload_has_a_summary():
    payload = demo()
    assert payload["summary"]["rules_fired"] == 49
    assert payload["summary"]["rules_total"] == 49


def test_self_check_runs_without_the_sdk():
    assert "6 MCP tools" in mcp_mod._self_check()


def test_build_server_registers_every_tool():
    pytest.importorskip("mcp", reason="the MCP extra is optional")
    import asyncio

    server = mcp_mod.build_server()

    async def go():
        tools = await server.list_tools()
        return sorted(t.name for t in tools)

    assert asyncio.run(go()) == sorted(TOOLS)

"""Shared helpers. Nothing here touches the network or the file system by surprise."""

from __future__ import annotations

import json
from pathlib import Path

from iamlint.analyze import Options, analyze_text
from iamlint.model import Report
from iamlint.parse import parse_policy

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def write_policy(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def dumps(obj) -> str:
    return json.dumps(obj, indent=2)


def scan(text: str, **kwargs) -> Report:
    """Analyse one document with the given Options fields overridden."""
    return analyze_text(text, "<test>", Options(**kwargs))


def scan_obj(obj, **kwargs) -> Report:
    return scan(dumps(obj), **kwargs)


def rules_of(report: Report) -> set[str]:
    return report.rules_fired()


def one(report: Report, rule: str):
    hits = [f for f in report.findings if f.rule == rule]
    assert hits, f"{rule} did not fire; got {sorted(rules_of(report))}"
    return hits[0]


def policy_of(text: str, path: str = "<test>"):
    return parse_policy(text, path)


def statement(**kwargs) -> dict:
    base = {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}
    base.update(kwargs)
    return base


def doc(*statements, version: str = "2012-10-17", **extra) -> str:
    body: dict = {"Version": version, "Statement": list(statements)}
    body.update(extra)
    return dumps(body)

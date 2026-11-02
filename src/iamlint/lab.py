"""A lab: six policies, each broken in one specific way.

Reading about IAM escalation is not the same as finding it. ``iamlint lab``
writes six short policies to a directory; every one of them has a real defect
and none of them is a trick - each is a shape that shows up in production
reviews. ``--check`` then proves the tool sees what the lab planted, so the lab
cannot silently rot when a rule changes.
"""

from __future__ import annotations

import os
import shutil

from .analyze import Options, analyze_paths
from .model import Report

LAB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "lab")

# What each challenge is meant to teach, printed by ``iamlint lab``.
LAB_NOTES: dict[str, str] = {
    "escalation-chain.json": "Neither statement is admin. Together they are: mint a key, then attach a policy to it.",
    "public-bucket.json": "Principal '*' plus a write action - the bucket is writable by anyone with an AWS account.",
    "confused-deputy.json": "Cross-account trust with no ExternalId, and a wildcard service principal.",
    "wildcard-verb.json": "iam:Create* grows with every verb AWS ships; the region wildcard hides which region.",
    "pass-role-lambda.json": "PassRole plus lambda:UpdateFunctionCode is remote code execution as the passed role.",
    "syntax-trap.json": "A trailing comma. AWS rejects the whole document and nothing else in it gets reviewed.",
}

LAB_README = """# iamlint lab

Six IAM policies, each with one real defect. No AWS account and no network
needed - run the tool against this directory:

    iamlint .
    iamlint . --bundle     # treat every file here as attached to one principal

| file | what is wrong with it |
|---|---|
{rows}

## Exercises

1. Run `iamlint .` and read the four lines of each finding: where, saw, fix, ref.
2. Fix one file, re-run, and watch the finding disappear from the report but stay
   in `git diff` - the fix is the reviewable artefact, not the report.
3. Run `iamlint . --bundle`. Which findings only appear once the policies are
   considered together, and what does that say about reviewing one policy at
   a time?
4. Delete the `Condition` from a fixed file and look at `IAM052` - a privileged
   action with nothing narrowing it.
"""


def lab_files() -> list[str]:
    if not os.path.isdir(LAB_DIR):
        return []
    return sorted(name for name in os.listdir(LAB_DIR) if name.endswith(".json"))


def lab_readme() -> str:
    rows = "\n".join(f"| `{name}` | {LAB_NOTES.get(name, '')} |" for name in lab_files())
    return LAB_README.format(rows=rows)


def write_lab(out_dir: str) -> list[str]:
    """Copy the challenges into ``out_dir``. Returns the files written."""
    os.makedirs(out_dir, exist_ok=True)
    written: list[str] = []
    for name in lab_files():
        src = os.path.join(LAB_DIR, name)
        dst = os.path.join(out_dir, name)
        shutil.copyfile(src, dst)
        written.append(dst)
    readme = os.path.join(out_dir, "README.md")
    with open(readme, "w", encoding="utf-8") as fh:
        fh.write(lab_readme())
    written.append(readme)
    return written


def check_lab(out_dir: str | None = None) -> Report:
    """Analyse the lab (the shipped files, or a directory written earlier)."""
    target = out_dir or LAB_DIR
    return analyze_paths([target], Options())


def lab_summary(report: Report) -> str:
    lines = ["iamlint lab - every file must produce at least one finding", ""]
    by_file: dict[str, list[str]] = {}
    for finding in report.findings:
        by_file.setdefault(os.path.basename(finding.file), []).append(finding.rule)
    for name in lab_files():
        rules = sorted(set(by_file.get(name, [])))
        status = "ok " if rules else "MISS"
        lines.append(f"  [{status}] {name:26} {', '.join(rules) if rules else 'no findings - the lab is broken'}")
    missing = [name for name in lab_files() if not by_file.get(name)]
    lines.append("")
    lines.append(f"{len(lab_files()) - len(missing)}/{len(lab_files())} challenges detected")
    return "\n".join(lines)

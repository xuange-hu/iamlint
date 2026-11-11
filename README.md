# iamlint

[![CI](https://github.com/xuange-hu/iamlint/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/iamlint/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/tests-295%20passing-brightgreen)](https://github.com/xuange-hu/iamlint/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](https://github.com/xuange-hu/iamlint/blob/main/pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Audit AWS IAM policies with the line, column and bytes that prove each finding.**

49 rules, zero dependencies, a second pass that reads your statements *together*
instead of one at a time, and a lab you can run without an AWS account.

```console
$ iamlint policies/
== policies/ci-runner.json
[CRIT] IAM030  Credential minting plus policy write: full escalation chain
    where : policies/ci-runner.json:7:17 (/Statement/0/Action)
    saw   : 'iam:CreateAccessKey' (statement 0) + 'iam:AttachUserPolicy' (statement 1)
    with  : policies/ci-runner.json:13:18 (statement 1)
    fix   : Break the pair: keep one of 'iam:CreateAccessKey' / 'iam:AttachUserPolicy', scope it, or remove it.
    ref   : MITRE ATT&CK T1078.004 Valid Accounts: Cloud Accounts / AWS privesc primitives
```

Every finding is four lines - **where**, **saw**, **fix**, **ref** - so a
reviewer can re-derive it from the file instead of trusting the tool. Findings
that only exist between two statements get a fifth line naming the partner,
because "remove one of these two" is not actionable if you cannot see both.

---

## Contents

- [Why a second pass](#why-a-second-pass)
- [Run it in three steps](#run-it-in-three-steps)
- [Commands](#commands)
- [The rules (49)](#the-rules-49)
- [What makes it different](#what-makes-it-different)
- [Install](#install)
- [Reading the output](#reading-the-output)
- [Docs](#docs)

## Why a second pass

Read this policy one statement at a time and nothing looks alarming:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "RotateKeys", "Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
    {"Sid": "AttachPol",  "Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}
  ]
}
```

`iamlint` reports `IAM030` at *critical*, names both statements, and tells you
to break the pair. Eight escalation shapes are detected this way
(`IAM030`-`IAM037`): credential minting plus policy write, role creation plus
policy write, policy-version hijack, `iam:PassRole` plus Lambda/EC2/ECS/Glue,
trust rewrite plus assume, password reset plus policy write, and boundary
removal plus policy write.

`--bundle` does the same across *files*, which is the honest model for a
principal: what matters is the union of what is attached to it.

## Run it in three steps

```bash
pip install iamlint          # or: pipx install iamlint
iamlint ./policies           # 1. point it at a file or a directory
iamlint demo                 # 2. see every rule fire, no AWS account needed
iamlint lab --out ./iam-lab  # 3. six exercises, each broken in one way
```

Nothing else to install, nothing to configure, no credentials. The demo and the
lab read checked-in text: **no network call leaves your machine**.

## Commands

| command | what it does |
|---|---|
| `iamlint PATH...` | scan files and directories (`.json`), exit 1 on findings |
| `iamlint demo` | the built-in broken policies: all 49 rules, offline |
| `iamlint lab [--out DIR]` | six challenges plus a README, then prove they are caught |
| `iamlint rules [--category CAT]` | the rule catalogue |
| `--json` / `--compact` | machine output / one line per finding |
| `--sarif FILE` | SARIF 2.1.0 for GitHub code scanning |
| `--min-severity`, `--fail-on` | noise floor and CI gate |
| `--ignore IAM071` / `.iamlint-ignore` | suppression (JSON has no comments) |
| `--only`, `--skip` | filter by category |
| `--bundle` | treat every input as attached to one principal |
| `--no-graph` | pass 1 only |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage error.

In a workflow:

```yaml
- name: IAM policy audit
  run: |
    pip install iamlint
    iamlint policies/ --sarif iamlint.sarif --fail-on high
- name: Upload
  uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: iamlint.sarif }
```

## The rules (49)

| category | ids | what it looks at |
|---|---|---|
| wildcard | IAM001-008 | `Action: "*"`, `iam:*`, `Resource: "*"`, `Principal: "*"`, `NotAction`/`NotResource`, `iam:Create*`, assume-any-role |
| escalation | IAM010-020 | the eleven primitives every published privesc path is built from |
| graph | IAM030-037 | combinations across statements (and across files with `--bundle`) |
| trust | IAM040-045 | public trust, missing `ExternalId`, wildcard accounts, wildcard services, unpinned OIDC/SAML |
| condition | IAM050-054 | `/0` source IPs, wildcard condition values, MFA-absent, `Null`, no condition at all |
| resource | IAM060-064 | missing Resource, non-ARN, `*` over secrets, wildcard account/region |
| hygiene | IAM070-075 | old Version, missing/duplicate Sid, duplicate JSON keys, syntax errors, size quota |

Run `iamlint rules` for the full list with severities, or
`iamlint rules --category trust`.

## What makes it different

- **Zero dependencies.** The JSON reader is hand-written and keeps every
  value's line, column and JSON Pointer, so a finding points at a byte, not at
  a file. It also reports the mistakes AWS rejects silently - duplicate keys
  (the last one wins), trailing commas, comments.
- **Two passes.** Most IAM scanners read one statement at a time. The finding
  that costs you the account lives *between* two statements.
- **The lab ships with it.** `iamlint lab` writes six policies that are broken
  in the exact ways real reviews miss, and `--check` proves the tool still
  catches them.
- **MCP server.** `pip install "iamlint[mcp]"` gives Claude Code / Cursor /
  Cline six tools (`iamlint_scan_text`, `iamlint_scan_path`,
  `iamlint_privilege_paths`, `iamlint_rules`, `iamlint_explain`, `iamlint_demo`).
- **SARIF 2.1.0** with rule metadata generated from the rule table, so findings
  land in pull requests.

## Install

```bash
pip install iamlint                        # zero dependencies
pip install "iamlint[mcp]"                 # + the MCP server
pip install "git+https://github.com/xuange-hu/iamlint.git"   # straight from main
```

From source:

```bash
git clone https://github.com/xuange-hu/iamlint
cd iamlint
pip install -e .
pip install pytest && python -m pytest -q      # 295 tests
```

Requires Python 3.10+. No AWS account, no credentials, no network at runtime.

> **PyPI note.** `Publish to PyPI` in the Actions tab is red until Trusted
> Publishing is registered for the project on PyPI - the workflow itself is
> correct and uses OIDC. Until then, install from git as shown above; `pip
> install iamlint` will start working the moment the project is registered.

## Reading the output

| severity | meaning |
|---|---|
| critical | a complete path to account takeover |
| high | a primitive or a wildcard that materially widens blast radius |
| medium | a real weakness that needs context to exploit |
| low | hygiene: it will bite during the next review, not today |

Grade: `A` clean → `F` anything critical. `iamlint --min-severity high` is the
usual CI gate.

## Docs

- `README_CN.md` - this document in Chinese
- `CONTRIBUTING.md` - how to add a rule (registry + trigger + test)
- `SECURITY.md` - how to report a problem with the tool
- `docs/promotion.md` - launch copy, if you want to help spread it

MIT licensed.

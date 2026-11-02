# Security policy

## Scope

**iamlint** — AWS IAM policy audit — is a static analysis tool: it reads **IAM
policy documents in JSON** and prints a report. The security questions that
apply to it are the ones that apply to any tool that parses untrusted input.

Supported: the current release.

## What this tool does with your files

Nothing leaves your machine. There is no network client in the scanning path:
the tool opens the files you point it at, parses them, and writes a report. It
never writes to the files it reads, and it never calls AWS.

## Reporting a vulnerability in iamlint

Use [GitHub private vulnerability reporting](https://github.com/xuange-hu/iamlint/security/advisories)
on the Security tab. If private reporting is unavailable to you, open an issue
marked `security`.

Include:

1. the version (`iamlint --version`);
2. the input that triggers it — the actual policy is preferred over a description;
3. what you expected and what happened.

For a parse failure, the smallest input that reproduces it is the whole report.

## What counts as a vulnerability here

- **A line or column that is off by one.** The JSON reader is hand-written; a
  wrong address sends the reader to the wrong statement.
- **A construct that is silently dropped** — a duplicate key where the wrong
  value wins, a `Principal` shape that is not normalised.
- **A wildcard that is not matched** — `iam:Put*` must reach `iam:PutUserPolicy`.
  Missing it means missing an escalation path.
- **A path that escapes the directory it was pointed at.**

## What does not count

- A rule firing on a policy you consider correct. That is a false positive:
  open an issue with the sample and it gets a regression test.
- A rule you want added. Open an issue or a PR — see `CONTRIBUTING.md`.

## Timing

I triage within a week and will confirm receipt. If a fix needs to sit in a
branch for a while, the advisory goes out when the fix lands, not before.

# Launch copy for iamlint

Drafted, not sent. Posting is a decision for a human - these are the texts to
paste when the time is right.

## One-line pitch

> An IAM policy linter that reads your statements *together*: 49 rules, zero
> dependencies, and a second pass that catches the escalation paths no
> single-statement check can see.

## Show HN

Title: `Show HN: iamlint – IAM policy audit that catches what two statements do together`

```
I kept reviewing IAM policies one statement at a time, which is the only way a
diff lets you read them, and it hides the actual problem: no single statement
in this policy is wrong.

{
  "Statement": [
    {"Sid": "RotateKeys", "Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
    {"Sid": "AttachPol",  "Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}
  ]
}

Together they are: mint a key for someone, then attach admin to them. iamlint
runs a second pass over the *combinations* and reports it as one critical
finding naming both statements.

What it is:
- 49 rules over wildcards, escalation primitives, trust policies, conditions,
  resources and hygiene
- 8 escalation shapes detected across statements (and across files with --bundle)
- zero dependencies; the JSON reader is hand-written and keeps every value's
  line, column and JSON Pointer, so a finding points at a byte
- `iamlint demo` fires all 49 rules offline; `iamlint lab` writes six broken
  policies as exercises
- SARIF 2.1.0 for GitHub code scanning, and an optional MCP server

Every finding prints as where / saw / fix / ref, so you can verify it against
the file instead of trusting me.

pip install iamlint
```

Timing: Tuesday-Thursday, 21:00-22:00 China time (HN's US morning).

## Reddit r/aws + r/devops

Title: `iamlint: an IAM policy linter that reads statements together, zero deps`

```
Most IAM linters evaluate one statement at a time. The finding that costs you
the account lives between two statements:

  iam:CreateAccessKey  +  iam:AttachUserPolicy  ==  full escalation

iamlint runs a second pass over combinations and reports it as a single
critical finding naming both statements. 49 rules, zero dependencies (the JSON
parser is hand-written so findings carry line/column/JSON Pointer), SARIF for
code scanning, `iamlint lab` ships six broken policies as exercises.

pip install iamlint && iamlint demo
```

## X / Twitter thread

1. No single statement in this IAM policy is wrong. Together they are a full
   account takeover. `iamlint` reads your statements *together*.
2. 49 rules, zero dependencies, SARIF, MCP server. Every finding prints
   where / saw / fix / ref with the line, column and JSON Pointer.
3. `iamlint lab` writes six policies that are broken the way real reviews miss.
   No AWS account, no network.

## Awesome-list blurb

```
[iamlint](https://github.com/xuange-hu/iamlint) - Zero-dependency AWS IAM
policy auditor with a second pass that detects privilege-escalation
combinations across statements; SARIF and MCP support.
```

## Order of operations

1. Push, tag v0.1.0, register the PyPI project + trusted publisher (Publish
   workflow turns green).
2. Show HN first - it is the only one that can produce a step change.
3. Reddit the same day, in the sub's own voice.
4. X thread last; it decays fastest.

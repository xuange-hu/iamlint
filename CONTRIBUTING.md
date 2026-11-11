# Contributing

**iamlint** — AWS IAM policy audit — is small on purpose: a hand-written JSON
reader, deterministic rules, no dependencies. Contributions that keep it that
way are welcome.

## Setup

```bash
git clone https://github.com/xuange-hu/iamlint
cd iamlint
pip install -e ".[mcp]" pytest ruff
pytest                 # 295 tests
ruff check .
```

No `pip install` is needed to run the tests after a clone — the root
`conftest.py` puts `src/` on `sys.path`.

## Rules and where they live

`src/iamlint/rules.py` (IAM001…IAM075, 49 rules) is pass 1: everything decidable
from one statement. `src/iamlint/graph.py` is pass 2: escalation shapes that only
exist between two statements (or two files, with `--bundle`).

## Adding a rule

1. **Register it** in `src/iamlint/rules.py` with a severity, a category, a
   `why` and a `fix`. Everything else (SARIF metadata, `iamlint rules`, the MCP
   `explain` tool) reads from that registry.
2. **Implement the check** in pass 1, or in `graph.py` if it needs two statements.
3. **Add a trigger** to `TRIGGERS` in `tests/test_rules.py` and a negative case
   that proves it stays quiet when it should.
4. **Extend the demo** so the new rule fires: CI asserts the demo reaches all
   49 rules (`.github/workflows/ci.yml`, job `demo-contract`).
5. **Update the README** rule table and the test-count badge. The `badge-check`
   job fails when the badge and pytest disagree.

## House rules

- **No third-party imports in the core.** The zero-dependency promise is what
  makes this usable on a jump host. `mcp_server.py` imports the SDK inside
  `build_server()` and nowhere else.
- **Every finding carries evidence.** `where`, `saw`, `fix`, `ref`. A finding
  without a location is a bug, not a finding.
- **Parsing never raises at the API boundary.** A syntax error is a finding
  (IAM074) with a line and a column.
- **Tests do not need the network, AWS, or a fixture download.**

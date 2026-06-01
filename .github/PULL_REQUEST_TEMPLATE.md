<!-- Thanks for contributing to the Elder Mind Governance Harness. -->

## What & why
A short description of the change and the motivation.

## Type
- [ ] Bug fix
- [ ] New / expanded policy rule (closes a bypass)
- [ ] Feature
- [ ] Docs / collateral
- [ ] Refactor / chore

## Checklist
- [ ] `pip install -e ".[mcp,dev]"` and `python -m pytest tests/ -q` pass locally
- [ ] If I changed `policy.yaml`: added/updated tests in `tests/test_known_bypasses.py` (and false-positive cases) and updated `docs/STANDARDS-MAP.md`
- [ ] If I changed a claim or capability: kept it honest (no "compliant/certified/AI-powered/covers all 10/blocks prompt injection") and updated `THREAT_MODEL.md` if scope changed
- [ ] No internal/private references (the CI guard `test_no_internal_private_references` must pass)
- [ ] Signed off (DCO): commits include `Signed-off-by:` (see `CONTRIBUTING.md`)

## Standards / threat-model impact
Does this change what the gate enforces, audits, or cedes? If so, note the OWASP ASI / NIST RMF mapping and any THREAT_MODEL update.

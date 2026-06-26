# Governance

How decisions get made in the Elder Mind Governance Harness. This is a small,
early (0.1.0 alpha) project, so the model is deliberately lightweight.

## Maintainership

The project is maintained by **ZenBlue Pty Ltd t/a Cyber Elders**. Today it is effectively
single-maintainer ("BDFL-lite"): the maintainer has final say on what merges,
the release cadence, and the project's direction.

**We are looking for co-maintainers.** Sustained, high-quality contributions —
good PRs, helpful review, thoughtful issues — are the path to commit rights.
If you'd like to help maintain a part of the project (a harness adapter, the
policy ruleset, docs), open a Discussion and say so.

## How decisions are made

- **Small changes** (bug fixes, new policy rules, docs, a new harness adapter):
  open a PR. The maintainer reviews and merges. `CODEOWNERS` routes review of the
  load-bearing files (`decide.py`, `risk_engine.py`, `policy.yaml`,
  `STANDARDS-MAP.md`, `THREAT_MODEL.md`, CI) to the maintainer.
- **Breaking or contentious changes** (the CLI contract, the decision/JSON shape,
  the security posture, anything that changes what the gate enforces or cedes):
  open a **GitHub Discussion** as a lightweight RFC first, so the trade-off is
  visible before code is written.
- **Disagreement** is resolved by discussion; the maintainer decides if consensus
  isn't reached, and records the rationale in the PR/Discussion.

## Non-negotiables

These are project values, enforced in CI — a PR that breaks them won't merge:

1. **Honesty over hype.** No "compliant", "certified", "covers all 10", "blocks
   prompt injection", or "AI-powered" claims. The honesty gate enforces this.
   Claims stay at "aware"/"aligned"/"common patterns" (see `docs/STANDARDS-MAP.md`).
2. **Determinism + local-first.** The core `decide()` path stays pure, offline,
   and reproducible — no model, network, or randomness in the verdict.
3. **Honest scope.** New limitations get documented in `THREAT_MODEL.md`
   (including known bypasses), not hidden.

## Security

Report vulnerabilities privately — see [`SECURITY.md`](SECURITY.md). Do not open
a public issue for a security problem.

## Contributing & licensing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) (includes the DCO sign-off requirement).
Code is Apache-2.0; docs are CC BY 4.0 — see [`LICENSE`](LICENSE),
[`LICENSE-DOCS`](LICENSE-DOCS), and [`NOTICE`](NOTICE).

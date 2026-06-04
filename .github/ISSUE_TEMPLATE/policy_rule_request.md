---
name: Policy rule request (close a bypass)
about: Propose a new/expanded deterministic rule for a risky command the gate misses
title: "[policy] "
labels: policy
---

**The risky action that currently passes**
The exact command / target the gate should catch but doesn't:
```
<command or file target>
```
Current verdict (`eldermind check`):

**Why it's risky**
What harm it can do (and the OWASP Agentic ASI it maps to, if you know).

**Proposed rule / pattern**
A regex or glob idea, and the action (warn / ask / block). Remember the gate is a
deterministic pattern matcher — we can't enumerate *every* spelling, and some
gaps are intentionally documented in [`THREAT_MODEL.md` → Known bypasses](../../THREAT_MODEL.md#known-bypasses).

**False-positive check**
Legitimate commands that look similar and must NOT be blocked.

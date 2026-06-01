---
name: Bug report
about: Something isn't working as documented
title: "[bug] "
labels: bug
---

**What happened**
A clear description of the bug.

**To reproduce**
The exact command / tool call. For a gate decision, include the JSON:
```bash
echo '{"action":"bash","target":"…"}' | eldermind check
```
and the output (verdict, reason, decision id).

**Expected**
What you expected the gate / CLI to do.

**Environment**
- OS: (Windows / macOS / Linux + version)
- Harness: (Claude Code / OpenCode / Kiro / Cursor / other)
- `eldermind version`:
- Python:

**Is this a known bypass?**
Please skim [`THREAT_MODEL.md` → Known bypasses](../../THREAT_MODEL.md#known-bypasses) — if a risky command was *allowed*, it may be a documented non-goal (use the "policy rule request" template instead). A *vulnerability* should go to [Security Advisories](../../SECURITY.md), not a public issue.

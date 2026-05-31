---
name: eldermind-init
description: Guide a user through installing the Elder Mind governance harness into their coding agent. Use when the user says "set up Elder Mind", "install the governance harness", or asks their agent to wire up eldermind.
---

# Guided install — Elder Mind Governance Harness

You are helping the user install **Elder Mind**, a local-first agentic governance
harness, into their coding agent. Walk them through it conversationally, then run
the install for them. Keep it short — four questions, then act.

## What Elder Mind does (one line for the user)
A deterministic pre-tool-use gate that blocks risky tool calls (destructive
commands, force-push, remote code execution), optionally checks dependency
installs for known-compromised packages (OSV), surfaces threat patterns, and can
escalate high-risk calls to a multi-model "council" using **your own** model.

## Steps

1. **Detect the harness.** Determine which agent you are running in:
   - Claude Code → `claude-code`
   - OpenCode → `opencode`
   - Kiro → `kiro`
   If unsure, ask the user.

2. **Pick a governance tier** (controls how much is enforced vs surfaced):
   - `explorer` — minimal, learn the ropes
   - `practitioner` — sensible defaults (recommended)
   - `governed` — stricter, more asks
   - `operator` — maximum enforcement
   Ask the user, default `practitioner`.

3. **Offer supply-chain protection (opt-in).** Explain plainly:
   > "Want me to also check dependency installs against the OSV vulnerability
   > database? It catches known-compromised packages. It may make a network call
   > to api.osv.dev when you install something; it degrades to an offline list
   > otherwise. (yes/no)"
   Respect their answer — this is **off** unless they say yes.

4. **Council models (optional).** Ask:
   > "For high-risk reviews, Elder Mind can ask one or more models to deliberate.
   > By default it uses *your* current model. If you route across several models,
   > name them; otherwise we'll just use this one."
   Collect a comma-separated list or leave empty.

5. **Install.** Run the non-interactive installer with their answers:
   ```bash
   eldermind install <harness> [--supplychain]
   ```
   (The installer also writes `.eldermind/config.toml` with the tier and council
   models. If you set council models or a non-default tier, tell the user to set
   them in `.eldermind/config.toml` — or run `eldermind init <harness>` for the
   interactive wizard.)

6. **Verify together.** Run a harmless demo and show the result:
   ```bash
   echo '{"action":"bash","target":"git push --force origin main"}' | eldermind check
   ```
   Point out the `block` verdict, the OWASP ASI tag, the decision id, and that an
   entry was written to `.eldermind/audit.jsonl`.

## Important
- Never bypass or disable the gate on the user's behalf without asking.
- If `eldermind` is not installed, tell them: `pipx install eldermind` (or `pip install eldermind`).
- Supply-chain protection is the only feature that may touch the network, and only when enabled.

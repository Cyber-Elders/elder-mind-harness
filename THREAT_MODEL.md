# Threat Model

`eldermind` is a deterministic pre-tool-use gate for a **single coding agent**. This document states what it protects against, what it explicitly does not, and where the trust boundary lies. Read it before relying on the gate for anything that matters.

## What the gate is

A synchronous, in-process decision function invoked by a harness's pre-tool-use hook. On every governed tool call it: matches the call against a versioned policy, scores it (`impact × likelihood`), and returns allow / warn / ask / block, writing an audit entry. No model, no network, no daemon.

## Trust boundary

```
            ┌───────────────────────────────────────────────┐
            │  The harness (Claude Code / OpenCode / Kiro)  │
            │                                               │
   user ──► │  agent ──► [pre-tool hook] ──► eldermind │ ──► tool executes
            │                  │                             │
            │                  └── only calls routed through │
            │                      the hook are visible      │
            └───────────────────────────────────────────────┘
```

**The gate only sees tool calls the harness routes through its hook.** Anything that does not pass through that hook is invisible to the gate. This is the single most important limitation.

## In scope (what it mitigates)

| Threat | OWASP ASI | Mechanism |
|---|---|---|
| Destructive shell commands (`rm -rf /`, etc.) | ASI02 Tool Misuse | Deterministic pattern deny |
| Remote code execution (`curl … \| bash`, `/tmp` scripts) | ASI05 Unexpected Code Execution | Pattern deny |
| Force-push to protected branches | ASI02 Tool Misuse | Pattern deny |
| Secrets file read/write | ASI03 Identity & Privilege Abuse | Glob match → ask |
| Outbound data upload | ASI02 Tool Misuse | Pattern → warn/ask |
| Installing a known-compromised dependency (opt-in) | ASI04 Agentic Supply Chain | OSV check + curated override → block |
| High-risk goal/tool decisions (optional) | ASI01 Agent Goal Hijack | BYO-LLM council review → ask |

All decisions are auditable (`.eldermind/audit.jsonl`) with reproducible decision ids. Heuristic detectors additionally surface (and log) injection/SSRF/traversal patterns in tool args — surfacing, not a hard block.

## Out of scope (do NOT rely on the gate for these)

- **Prompt injection.** The gate does not classify natural-language injection. A novel injection that produces a benign-looking but harmful tool call will pass. Use a dedicated injection guardrail alongside it.
- **OS-level isolation.** Policy-level deny is not a sandbox. A determined agent or compromised tool that bypasses the harness hook (e.g. spawns a subprocess the harness never reports) is not gated.
- **Full software composition analysis.** Supply-chain checks query OSV for declared installs; they are not a substitute for `osv-scanner`/SBOM scanning in CI, and unpinned installs are only as good as what OSV knows.
- **Memory & context poisoning (ASI06).** Requires persistent-memory introspection; stateful, deferred.
- **Inter-agent communication (ASI07) and cascading failures (ASI08).** A single local hook cannot observe agent-to-agent traffic.
- **Human-agent trust exploitation (ASI09).** A social/UX-layer risk the gate does not address directly.
- **Rogue-agent drift (ASI10).** Behavioral drift detection requires runtime observation the gate does not perform.

## Assumptions

- The harness invokes the pre-tool hook for the tool classes configured (`Bash`, `Edit`, `Write`, `Read`, `MultiEdit` by default). Tools outside the matcher are not gated.
- The policy file and the `eldermind` binary are not tampered with. Protect `.eldermind/` and the installation as you would any local security config.
- The council uses the user's own model(s); its quality is bounded by that model. With no model configured it degrades to a human "ask".
- The user/operator reviews `ask` verdicts honestly rather than reflexively approving.

## Failure modes

- **Policy fails to load** → fail-safe to `ask` (configurable via `defaults.on_error`).
- **Malformed harness event** → fail-safe to exit 2 (block/ask), never silent allow.
- **Audit write fails** → the decision is still returned; the gate never blocks on a logging failure.

## Reporting issues

See [SECURITY.md](SECURITY.md).

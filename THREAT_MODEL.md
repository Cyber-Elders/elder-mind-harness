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
| Destructive shell commands (`rm -rf /`, `find … -delete`, etc.) | ASI02 Tool Misuse | Pattern deny — **common forms** (see [Known bypasses](#known-bypasses)) |
| Remote code execution (`curl … \| bash`, `bash <(curl …)`, `/tmp` scripts) | ASI05 Unexpected Code Execution | Pattern deny — common forms |
| Force-push to protected branches (`--force`, `-f`, `+ref`) | ASI02 Tool Misuse | Pattern deny — common forms |
| Disabling/blinding the gate (writing `.eldermind/`, hook config) | ASI03 Identity & Privilege Abuse | Pattern/glob → ask (**best-effort**, see [Self-protection](#self-protection--audit-integrity)) |
| Secrets file read/write | ASI03 Identity & Privilege Abuse | Glob match → ask (**filename-based**; content is not scanned) |
| Outbound data upload | ASI02 Tool Misuse | Pattern → warn/ask |
| Installing a known-compromised dependency (opt-in) | ASI04 Agentic Supply Chain | OSV check + curated override → block |
| High-risk goal/tool decisions (optional) | ASI01 Agent Goal Hijack | BYO-LLM council review → ask (**advisory MCP**, not the hard-gate hook) |
| Tool/MCP descriptor drift ("rug-pull") | ASI02 Tool Misuse | Descriptor pinning (TOFU) → flag on change |

All decisions are auditable (`.eldermind/audit.jsonl`) with reproducible decision ids. Heuristic detectors additionally surface (and log) injection/SSRF/traversal patterns in tool args — surfacing, not a hard block. The pattern rules are a **deny-known-bad tripwire**, not an allowlist: anything no rule matches is allowed (`defaults.unmatched: allow`), so the absence of a block is not a safety assertion.

## Out of scope (do NOT rely on the gate for these)

- **Prompt injection.** The gate does not classify natural-language injection. A novel injection that produces a benign-looking but harmful tool call will pass. Use a dedicated injection guardrail alongside it.
- **OS-level isolation.** Policy-level deny is not a sandbox. A determined agent or compromised tool that bypasses the harness hook (e.g. spawns a subprocess the harness never reports) is not gated.
- **Full software composition analysis.** Supply-chain checks query OSV for declared installs; they are not a substitute for `osv-scanner`/SBOM scanning in CI, and unpinned installs are only as good as what OSV knows.
- **Memory & context poisoning (ASI06).** Requires persistent-memory introspection; stateful, deferred.
- **Inter-agent communication (ASI07) and cascading failures (ASI08).** A single local hook cannot observe agent-to-agent traffic.
- **Human-agent trust exploitation (ASI09).** A social/UX-layer risk the gate does not address directly.
- **Rogue-agent drift (ASI10).** Behavioral drift detection requires runtime observation the gate does not perform.

## Assumptions

- The harness invokes the pre-tool hook for the tool classes the installer registers. The Claude Code matcher is `Bash|Edit|Write|Read|MultiEdit|NotebookEdit|WebFetch|Task|mcp__.*`; Kiro is `execute_bash|fs_write|fs_read`; OpenCode wraps `tool.execute.before`. **Tools outside the matcher are not gated** — including any built-in or MCP tool the matcher doesn't name. Widen the matcher if your harness exposes more.
- The policy file and the `eldermind` binary are not tampered with. The gate makes a *best-effort* attempt to gate writes to its own `.eldermind/` and the harness hook config (see below), but this is not a containment boundary — see Self-protection.
- The council uses the user's own model(s); its quality is bounded by that model. With the default single-model config it is a structured pause/re-prompt, not an independent judge; with no model configured it degrades to a human "ask".
- The user/operator reviews `ask` verdicts honestly rather than reflexively approving.

## Self-protection & audit integrity

Be clear-eyed about the core asymmetry: **the agent the gate governs runs with write access to the same disk the gate's policy and audit log live on.** A *cooperative-but-fallible* agent is what the gate is built for — it catches the mistaken `rm -rf`, the careless force-push, the compromised install. A *fully-compromised or deliberately-adversarial* agent is a different threat:

- **Self-protection is best-effort.** The `tamper-governance-config` rule + the `**/.eldermind/**` write glob flag (→ `ask`) shell/edit attempts to rewrite `.eldermind/policy.yaml`, delete `audit.jsonl`, flip the mode, or edit the harness hook config. This raises the bar but is **not** airtight — a process can still write those files by a route the patterns don't match (e.g. `python -c`). Treat `.eldermind/` and the hook config as security-sensitive: keep them read-only to the agent where your OS/harness allows, and in CI commit them so drift is reviewable.
- **The audit chain is tamper-EVIDENT, not tamper-PROOF.** `eldermind verify` detects accidental or partial edits (an altered line, a dropped entry) because the hash chain breaks. It does **not** detect a *full rewrite*: an attacker with local write can delete an entry and recompute every `prev`/`hash` from genesis plus `audit.head`, and `verify()` will then report "intact." There is no external anchor in the local file alone. To detect a full rewrite, **record the chain head off-box** — `eldermind verify` prints the current head hash for exactly this purpose (pin it in CI, a separate log sink, or a notebook).

This is the honest position for a local hook: it governs the moment of action for an agent that is not actively trying to defeat it, and it leaves a high-quality, accident-tamper-evident local record. It is not a sandbox or a containment boundary for a hostile process with local write — use OS isolation for that (see "Pairs with" in the README).

## Known bypasses

A deterministic pattern matcher only blocks the spellings its rules enumerate; an agent generates near-infinite surface-form variation. We **document** the known gaps rather than imply completeness — they are tracked in `tests/test_known_bypasses.py`, which asserts both what now blocks and what still slips, so the list can't silently rot.

Currently **allowed** (known, accepted for a local pattern gate):
- **Variable/indirect invocation** — `X=rm; $X -rf /`, `$(echo rm) -rf /`. The literal command name is hidden.
- **Heavy obfuscation** — `echo <base64> | base64 -d | bash`, `eval "$(…)"`. Decoding happens at runtime, after the gate sees the string. (The heuristic detectors may *surface* a command-substitution as `warn`, but the destructive intent is not hard-blocked.)
- **Equivalent forms not yet enumerated** — e.g. `rm -rf ./` (cwd via `./`), staged download-then-run (`curl -o x && ./x`), interpreters/tools outside the listed set.
- **Shelling around the hook** — a subprocess the harness never reports to the gate (the architectural boundary above).

Closing these by adding patterns is welcome (open a "policy rule request" issue), but the design assumption stands: this is a tripwire for common, accidental, or lazy-malicious actions — pair it with OS isolation and an injection guardrail for a hostile agent.

## Observe mode & tier relaxation (no false sense of security)

- **Observe mode** (`ELDERMIND_MODE=observe`, or `[governance] mode = "observe"`) **enforces nothing** — it logs the verdict that *would* have applied and proceeds. Every decision in observe mode is tagged and the reason is prefixed `OBSERVE MODE — NOTHING IS BLOCKED`. It is for onboarding/measurement only; you are **not** protected until you turn it off.
- The **`explorer`** tier deliberately relaxes `ask → warn` for low friction (a hard `block` is never relaxed). That means credential-file reads that would `ask` under `practitioner` only `warn` under `explorer` — surfaced and logged, but not gated. Choose `practitioner` or stricter when you want the prompt.

## Failure modes

- **Policy fails to load** → fail-safe to `ask` (configurable via `defaults.on_error`).
- **Malformed harness event** → fail-safe to exit 2 (block/ask), never silent allow.
- **Audit write fails** → the decision is still returned; the gate never blocks on a logging failure.
- **Unmatched call** → allowed (`defaults.unmatched: allow`). This is fail-open by design for usability; set the `operator` tier and add rules for a stricter posture.

## Reporting issues

See [SECURITY.md](SECURITY.md).

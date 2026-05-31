<p align="center">
  <img src="docs/assets/logo-banner.png" alt="Elder Mind — Agentic Governance by Cyber Elders" width="640">
</p>

# Elder Mind Governance Harness

**Local-first agentic governance for coding agents.** A deterministic pre-tool-use gate that blocks risky actions, checks dependency installs for known-compromised packages, surfaces threat patterns, and can escalate high-risk calls to a multi-model "council" — all running on *your* machine with *your* model. Hard-blocks in **Claude Code, OpenCode, and Kiro**; advisory in **Cursor** and any MCP client — on **Windows, macOS, and Linux**. ([IDE × OS matrix](docs/IDE-SUPPORT.md))

[![License](https://img.shields.io/badge/code-Apache--2.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-CC--BY--4.0-lightgrey.svg)](LICENSE-DOCS)
[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](CHANGELOG.md)
[![CI](https://img.shields.io/badge/CI-regression%20%2B%20UAT%20%C2%B7%20mac%2Fwin%2Flinux-blue.svg)](.github/workflows/ci.yml)
[![Tested](https://img.shields.io/badge/tests-83%20%C2%B7%203%20personas%20%C2%B7%20docs-brightgreen.svg)](docs/TESTING.md)
[![Standards](https://img.shields.io/badge/OWASP_Agentic_2026-aware-green.svg)](docs/STANDARDS-MAP.md)
[![NIST](https://img.shields.io/badge/NIST_AI_RMF-aligned-green.svg)](docs/STANDARDS-MAP.md)

```
⛔ Elder Mind blocked: bash(git push --force origin main)
   risk 16/25 (elevated_review) · OWASP ASI02 Tool Misuse · NIST RMF: MANAGE
   decision EM-2169fd82a466 · audit .eldermind/audit.jsonl
```

---

## Why it's different

Most agent-safety tools are **input/output guardrails** (filter prompts and outputs) or **cluster control planes** (govern deployed agent workloads). Elder Mind is neither.

> **Governance that runs as your coding agent's own pre-tool-use hook — local, deterministic, and auditable on your machine — not a control plane your agent has to phone home to.**

- **Local + deterministic.** The verdict is plain arithmetic (`impact × likelihood`) over a versioned policy file. Same input, same decision, reproducible offline — no model in the decision path, no drift.
- **At the tool-call boundary.** It governs the exact moment your agent decides to run `rm -rf`, force-push, or `curl … | bash` — inside the dev loop, not at a deployment ring.
- **Bring your own LLM.** The optional multi-model "council" review uses *your* agent's model (and any models you already route to). Elder Mind ships **no API keys and makes no cloud calls of its own** — the one exception is the optional supply-chain check, which queries the public OSV database and only when you turn it on.
- **60-second install** into the three agents you already use, guided by your own AI.

---

## Quick start

```bash
# Pre-release (not yet on PyPI) — install from source:
git clone <repo-url> && cd elder-mind-harness && pipx install .   # or: pip install .
# Once published this becomes simply:  pipx install eldermind

eldermind init claude-code      # guided setup — or: opencode | kiro | cursor
```

`init` walks you (and your agent) through harness detection, a governance tier, optional supply-chain protection, and council models — then wires the pre-tool hook and writes `.eldermind/`. Prefer non-interactive? `eldermind install claude-code --supplychain`.

Try the gate with no agent at all:

```bash
echo '{"action":"bash","target":"git push --force origin main"}' | eldermind check
# -> {"verdict":"block","asi":"ASI02", ...}   exit code 2
```

---

## What's in the harness

| Capability | What it does | Network? |
|---|---|---|
| **Pre-tool gate** | Deterministic `impact × likelihood` → allow / warn / ask / block on a versioned `policy.yaml`. Hard-blocks destructive deletes, force-push to protected branches, `curl\|bash`, secrets read/write. | No |
| **Supply-chain** (opt-in) | On `npm/pip/cargo/...` installs, checks each package against the **OSV** database (+ OpenSSF malicious-packages) with an offline curated fallback, and optionally flags **brand-new versions** (release-age, via deps.dev). Catches known-compromised + suspiciously-fresh packages. | OSV / deps.dev when enabled; degrades offline |
| **Threat detectors** | Heuristic regex surfacing (command-substitution, SSRF-to-metadata, path traversal, …), MITRE-tagged, written to the audit trail. Surfaces — does not hard-block legit code. | No |
| **Council review** (BYO-LLM) | For high-risk calls, an MCP tool hands *your* model a structured deliberation task; with model routing, votes are combined by a consensus rule. No model? Falls back to asking you. | Uses your model only |
| **Tool-descriptor pinning** | Pins a hash of each MCP/tool descriptor on first use; flags drift ("rug-pulls") if name/schema/command/args/origin change after approval. | No |
| **Audit trail** | Append-only, **hash-chained** `.eldermind/audit.jsonl` (tamper-evident — `eldermind verify`); reproducible decision ids; `eldermind summary` aggregates; `eldermind explain <id>` reconstructs a decision. | No |

**Governance tiers** modulate strictness deterministically: `explorer` (low friction — ask→warn, but never relaxes a block), `practitioner` (default, knowledge-worker safe), `governed` (warn→ask), `operator` (strictest — warn→ask, ask→block). **Observe mode** (`ELDERMIND_MODE=observe`) logs what *would* have happened but never blocks — friction-free onboarding.

Two ways it plugs in: a **pre-tool hook** (the hard gate — Claude Code `PreToolUse`, OpenCode `tool.execute.before`, Kiro `preToolUse`) and an **advisory MCP server** (`govern_check`, `council_review`, `scan`, `pin_check`, `audit_log`, `audit_summary`) usable from any MCP client.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the wedge, runtime loop, component, and decision-engine diagrams.

---

## Who it's for

| You are… | What you get |
|---|---|
| **A solo developer** running an agent 24/7 | A safety net that blocks the destructive command you didn't see coming — zero infra, install in a minute. |
| **A team lead** rolling out coding agents | A versioned `policy.yaml` in the repo so every teammate's agent obeys the same rules, with an audit trail. |
| **A security / risk owner** | Deterministic, reproducible decisions mapped to OWASP Agentic 2026 + NIST AI RMF, an offline audit log, and an honest threat model. |
| **An air-gapped / privacy-sensitive shop** | Works offline; no keys, no telemetry, no cloud — the council uses *your* model, the supply-chain check is opt-in. |

---

## Standards posture (honest)

Elder Mind is **OWASP Agentic Top 10–aware** and **aligned to the NIST AI RMF four-function structure** (GOVERN / MAP / MEASURE / MANAGE). It is **not** "compliant", "certified", or a complete control set — a local pre-tool hook structurally cannot address everything a cluster overlay can, and we say so. Full rule-by-rule mapping: [`docs/STANDARDS-MAP.md`](docs/STANDARDS-MAP.md).

| | OWASP Top 10 for Agentic Applications (2026) |
|---|---|
| **Enforce** | ASI02 Tool Misuse · ASI04 Agentic Supply Chain · ASI05 Unexpected Code Execution |
| **Enforce / audit** | ASI03 Identity & Privilege Abuse |
| **Improve (council)** | ASI01 Agent Goal Hijack (human/multi-model review) |
| **Out of scope** (documented) | ASI06 Memory Poisoning · ASI07 Inter-Agent Comms · ASI08 Cascading Failures · ASI09 Human-Agent Trust · ASI10 Rogue Agents |

> Reference: OWASP GenAI Security Project — *OWASP Top 10 for Agentic Applications* (2026, final 1.0, 2025-12-09).

---

## What it does NOT do

This defines the trust boundary — please read it. See [`THREAT_MODEL.md`](THREAT_MODEL.md).

- **Not a prompt-injection classifier.** It matches command/tool patterns deterministically; pair it with an injection guardrail if you need that.
- **Not "AI-powered."** The gate verdict is arithmetic — that's the point (reproducible, explainable, offline).
- **Not a kernel sandbox.** Rules are policy-level deny/ask, not OS isolation. If an agent shells out around the hook, the gate doesn't see that call.
- **Not a multi-agent monitor.** Inter-agent communication and rogue-agent drift need a runtime overlay.
- **Supply-chain is not a full SCA.** It checks installs against OSV; it is not a substitute for `osv-scanner`/SBOM in CI (though `eldermind scan <lockfile>` will use `osv-scanner` if you have it).

---

## Pairs with (defense in depth)

Elder Mind governs **the action**, one layer after a prompt is formed. It deliberately doesn't try to be everything — pair it with:

- **Prompt-injection / I-O guardrails** — Lakera, NVIDIA NeMo Guardrails, Meta LlamaFirewall, LLM Guard. They reduce malicious *intent* reaching the model; Elder Mind governs the *tool call* if something slips through.
- **Full software-composition analysis** — `osv-scanner`, Socket, Snyk in CI for lockfile/SBOM scanning. Elder Mind catches known-bad packages at the *install moment*; SCA covers the whole tree.
- **Observability / evals** — Langfuse, LangSmith, Arize Phoenix for traces and quality. Elder Mind keeps the *enforcement + local audit* minimal and offline.
- **OS isolation** — run agents in a container / restricted workspace with egress controls. The gate is policy-level, not a kernel sandbox.

The category framing: **local pre-action governance for coding agents** — the safety harness for the moment an agent is about to act, complementing (not replacing) enterprise control planes and guardrail filters.

---

## Commands

| Command | Purpose |
|---|---|
| `eldermind init <tool>` | Guided install (interactive). |
| `eldermind install <tool> [--supplychain]` | Non-interactive install. |
| `eldermind check '<json>'` | Evaluate a tool call (the universal hook target). Exit 0 allow/warn, 2 ask/block. |
| `eldermind scan <install-cmd\|lockfile>` | Supply-chain check (OSV). |
| `eldermind explain <decision-id>` | Reconstruct a past decision from the audit log. |
| `eldermind verify` | Verify the audit chain is intact (tamper-evident). |
| `eldermind pin <list\|check\|reset>` | Pin tool/MCP descriptors and detect drift. |
| `eldermind serve` | Advisory MCP server (needs `[mcp]` extra). |
| `eldermind summary` | Audit aggregate metrics (NIST MEASURE). |
| `eldermind version` | Print the installed version. |

---

## License

Code is **Apache-2.0** ([LICENSE](LICENSE)). Documentation and methodology are **CC BY 4.0** ([LICENSE-DOCS](LICENSE-DOCS)).

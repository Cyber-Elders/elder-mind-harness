# Changelog

All notable changes to the Elder Mind Governance Harness.

## [0.1.0] — unreleased

First public release: the flagship local-first agentic governance harness for coding agents (Claude Code, OpenCode, Kiro).

### Added
- **Pre-tool gate** — deterministic `impact × likelihood` (1–25) scoring + escalation router (`auto_approve` / `notify_after` / `review` / `elevated_review` / `block_critical`) → verdict `allow`/`warn`/`ask`/`block`, with content-addressed (reproducible, offline) decision ids. Default `policy.yaml` covers destructive deletes, `curl|bash`, `/tmp` script execution, force-push to protected branches, and secrets read/write.
- **Supply-chain protection** (opt-in) — on package installs, checks each package against the **OSV.dev** API (+ OpenSSF malicious-packages) with a curated offline override blocklist; subshell-bypass aware. Maps to OWASP ASI04. `eldermind scan` for ad-hoc checks; `osv-scanner` used for lockfile scans when present.
- **Threat detectors** — heuristic, MITRE-tagged regex surfacing (command-substitution, SSRF-to-metadata, path traversal, …) over tool arguments; recorded to the audit trail (surfacing, not a hard block).
- **BYO-LLM council review** — high-risk calls can be routed to a multi-model deliberation run by the user's *own* model via the `council_review` MCP tool; consensus over configured models, or degrades to a human "ask". No API keys shipped.
- **Audit trail** — append-only `.eldermind/audit.jsonl` with reproducible decision ids; `eldermind summary` aggregates (NIST RMF MEASURE).
- **Guided install** — `eldermind init` interactive wizard + an AI-guided `skills/eldermind-init` the user's lead agent reads to walk them through setup (harness, tier, supply-chain opt-in, council models).
- **CLI** (`eldermind`) — `init`, `install`, `check` (universal hook target), `hook <tool>`, `scan`, `serve`, `summary`, `version`.
- **MCP server** (`govern_check`, `council_review`, `scan`, `audit_log`, `audit_summary`) — advisory path, universal across MCP clients (optional `[mcp]` extra).
- **Harness adapters** — hard-enforcement pre-tool hooks for Claude Code (`PreToolUse`), OpenCode (`tool.execute.before` plugin), and Kiro (`preToolUse` agent hook). Idempotent installer.
- **Docs** — flagship README, `THREAT_MODEL.md`, `docs/STANDARDS-MAP.md` (honest OWASP-2026/NIST-RMF mapping), `SECURITY.md`; Apache-2.0 (code) + CC BY 4.0 (docs).

### Standards posture
- OWASP Top 10 for Agentic Applications (2026, final 1.0): **enforce** ASI02/ASI04/ASI05, **enforce/audit** ASI03, **improve** ASI01 (council); **out of scope** ASI06/07/08/09/10 (documented in the threat model).
- "Aware" / "aligned to the structure" — never "compliant", "certified", "covers all 10", "blocks prompt injection", or "AI-powered".

### Known limitations
- Kiro adapter is best-effort pending live-harness verification of the `preToolUse` payload schema.
- Supply-chain protection is the only feature that may touch the network, and only when enabled.

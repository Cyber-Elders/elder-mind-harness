# Standards Map

How the Elder Mind Governance Harness relates to the OWASP Agentic Top 10 and the NIST AI RMF — stated honestly, so the claims survive a skeptical reviewer.

**Claim ceiling.** This tool is **OWASP Agentic Top 10–aware** and **aligned to the NIST AI RMF four-function structure**. It is *not* "compliant," "certified," or a complete control set. A single local, in-process pre-tool hook cannot enforce risks that require cluster-level or multi-agent observation; those are listed as out of scope, not quietly claimed.

> **Reference taxonomy:** OWASP GenAI Security Project — *OWASP Top 10 for Agentic Applications* (2026, final 1.0, published 2025-12-09). Source: `https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/`. This is the agentic taxonomy, **not** the legacy LLM-Top-10 reskin.

## OWASP Top 10 for Agentic Applications (2026) — coverage

Legend: **enforce** = a policy rule can block/ask · **audit** = surfaced and logged, not blocked · **improve** = the council adds human/multi-model review · **out** = out of scope for a local pre-tool gate.

| ASI | Official title | Coverage | How / why |
|-----|----------------|----------|-----------|
| ASI01 | Agent Goal Hijack | **improve** | Not detectable by a deterministic gate, but high-risk calls can be routed to BYO-LLM council review for a second opinion. Pair with an injection classifier for detection. |
| ASI02 | Tool Misuse | **enforce** | Core. Destructive shell commands, force-push to protected branches, and data-exfil curl are denied at the tool boundary. |
| ASI03 | Identity & Privilege Abuse | **enforce / audit** | Secrets and private-key read/write are gated to `ask` and logged. Credential *use* beyond file access is audit-only. |
| ASI04 | Agentic Supply Chain Vulnerabilities | **enforce** (opt-in) | Package installs are checked against the OSV database (+ OpenSSF malicious-packages) with an offline curated override; known-compromised versions are blocked. Off by default; enabled at install. |
| ASI05 | Unexpected Code Execution | **enforce** | `curl … \| bash`-style remote code execution and `/tmp` script execution are denied. |
| ASI06 | Memory & Context Poisoning | **out** | Requires persistent-memory introspection; stateful, deferred. |
| ASI07 | Insecure Inter-Agent Communication | **out** | A single local hook cannot see agent-to-agent traffic. Needs a runtime overlay. |
| ASI08 | Cascading Failures | **out** | A multi-agent / runtime-orchestration concern. |
| ASI09 | Human-Agent Trust Exploitation | **out** | Social/UX-layer risk; the `ask` verdict surfaces decisions to a human but does not address trust exploitation directly. |
| ASI10 | Rogue Agents | **out** | Behavioral drift detection requires runtime observation the gate does not do. |

Net: **3 enforce (ASI02, ASI04, ASI05) · 1 enforce/audit (ASI03) · 1 improve (ASI01) · 5 out of scope.** Ceding the out-of-scope items openly is deliberate — it is what makes the in-scope claims credible.

Threat detectors (`detectors.py`) add heuristic **surfacing** of injection / SSRF / traversal patterns in tool arguments (MITRE-tagged), recorded to the audit trail. They are not a hard gate (they would false-positive on legitimate developer code) — hard blocks stay with the deterministic policy rules.

## NIST AI RMF — function mapping

Each function maps to an **inspectable artifact**, not a label.

| RMF function | Artifact in the harness |
|---|---|
| **GOVERN** | The versioned `policy.yaml` + `.eldermind/config.toml` + this document + `THREAT_MODEL.md`. Governance is written down and version-controlled. |
| **MAP** | The `asi` field on every policy rule + the supply-chain/detector → ASI mapping (the tables here are generated from it). |
| **MEASURE** | The append-only `audit.jsonl` (decision ids, scores, ASI tags, detector findings, supply-chain results) **plus** `eldermind summary` aggregates. Metrics over time, not just a raw log. |
| **MANAGE** | The pre-tool gate (allow/warn/ask/block + escalation tier), the supply-chain block, and the council review are the risk response. |

This is *alignment to the four-function structure*, not an RMF assessment or certification.

## Rule → standard crosswalk (default policy + capabilities)

| Source | OWASP ASI | NIST function | Action |
|---|---|---|---|
| `destructive-recursive-delete` | ASI02 Tool Misuse | MANAGE | block |
| `remote-code-execution` (`curl\|bash`) | ASI05 Unexpected Code Execution | MANAGE | block |
| `tmp-script-execution` | ASI05 Unexpected Code Execution | MANAGE | block |
| `git-force-push-protected` | ASI02 Tool Misuse | MANAGE | block |
| `write-secrets-file` / `read-cloud-credentials` | ASI03 Identity & Privilege Abuse | MANAGE / MEASURE | ask |
| `write-agent-or-ci-config` (.claude/.vscode/.mcp/CI) | ASI03 Identity & Privilege Abuse | MANAGE / MEASURE | ask |
| `outbound-data-upload` | ASI02 Tool Misuse | MEASURE | warn |
| supply-chain (OSV) on installs | ASI04 Agentic Supply Chain | MANAGE / MEASURE | block (opt-in) |
| threat detectors (regex) | ASI02 / ASI05 (heuristic) | MEASURE | warn (surface) |
| council review | ASI01 Agent Goal Hijack | MANAGE | ask (BYO-LLM) |
| tool-descriptor pinning | ASI02 Tool Misuse (rug-pull / deceptive tool) | GOVERN / MEASURE | new/ok/changed (TOFU + drift) |

Governance **tiers** (`explorer`/`practitioner`/`governed`/`operator`) and **observe mode** modulate how the MANAGE response is applied — deterministically, never relaxing a hard block.

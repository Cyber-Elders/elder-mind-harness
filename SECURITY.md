# Security Policy

## Reporting a vulnerability

Please report security issues privately. Do **not** open a public issue for a vulnerability.

- Preferred: open a private advisory via GitHub Security Advisories ("Report a vulnerability" on the repo's Security tab).
- Include: affected version, a description, and a minimal reproduction if possible.

We aim to acknowledge reports within 5 working days.

## Scope

`eldermind` is a deterministic, local pre-tool-use gate. Before reporting, please read [`THREAT_MODEL.md`](THREAT_MODEL.md) — several "bypasses" (prompt injection, shelling around the harness hook, multi-agent traffic) are **documented non-goals**, not vulnerabilities.

In scope for security reports:
- The gate returning `allow` for a tool call that a shipped policy rule should have matched (a matcher/regex flaw).
- A policy file or crafted harness event that causes the gate to crash open (silent allow) instead of failing safe.
- Path/glob handling that lets a secrets-file rule be trivially evaded.
- The audit log being silently corruptible such that a blocked action leaves no trace.

Out of scope (see threat model): prompt-injection classification, OS sandboxing, inter-agent / rogue-agent detection, output filtering, supply-chain provenance.

## Supported versions

Alpha (0.1.x): latest minor only.

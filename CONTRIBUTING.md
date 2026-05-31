# Contributing to the Elder Mind Governance Harness

Thanks for helping improve local-first agentic governance. This repo is the **runtime harness** (a Python package + MCP server + harness adapters). Contributions of policy rules, harness adapters, detectors, and docs are all welcome.

## Ground rules (non-negotiable)

These keep the project honest and the product's core promise intact:

1. **The gate stays deterministic and offline.** `decide()` must not make network calls, use randomness, or depend on wall-clock time — same input, same verdict, same decision id. The only feature allowed to touch the network is the opt-in supply-chain check, and it lives outside `decide()` (in `gate.py`).
2. **No model, no keys in the decision path.** The council uses the *user's own* LLM via MCP. We never ship API keys or call a cloud model ourselves.
3. **No overclaiming.** Never describe the tool as "compliant", "certified", "covers all 10 OWASP risks", "blocks prompt injection", or "AI-powered". It is *OWASP-Agentic-aware* and *aligned to* the NIST RMF structure. The CI honesty job enforces this.
4. **Honest OWASP taxonomy.** Use the OWASP Top 10 for Agentic Applications (2026) titles (see `docs/STANDARDS-MAP.md`). Do not reintroduce the legacy LLM-Top-10 reskin.

## Dev setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[mcp,dev]"
pytest -q
```

## What to contribute

- **Policy rules** — edit `eldermind/policy.yaml`. Each rule needs an `id`, an `asi` tag (valid ASIxx), `impact`/`likelihood` (1–5), and an `action` floor. Add a test in `tests/`.
- **Harness adapters** — a new coding agent? Add a translator in `eldermind/harness.py` and an installer branch in `eldermind/install.py`, plus a reference config under `adapters/`.
- **Detectors** — heuristic regex in `eldermind/detectors.py`. Keep them **surfacing** (warn/ask), not hard blocks — they run on developer tool args and must not false-block legitimate code.
- **Supply-chain** — `eldermind/supplychain.py`. OSV is authoritative online; the bundled `blocklist.json` is the offline curated override (exact pinned versions only).
- **Docs** — README/THREAT_MODEL/STANDARDS-MAP. Keep the "what it does NOT do" section truthful.

## Before you open a PR

- `pytest -q` passes.
- New behaviour has a test (boundary + a negative case).
- If you touched claims/docs, the CI **honesty** job still passes (it rejects overclaim phrasing and the legacy OWASP taxonomy — see `.github/workflows/ci.yml`).
- One logical change per PR; explain the threat/UX rationale.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Don't open public issues for vulnerabilities.

## License

Code contributions are under **Apache-2.0**; docs under **CC BY 4.0** (see `LICENSE` / `LICENSE-DOCS`). By contributing you agree your work is licensed accordingly.

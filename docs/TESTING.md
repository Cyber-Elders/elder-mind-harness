# Testing strategy

How the harness is tested: a layered pyramid run on **macOS, Windows, and Linux**
via GitHub Actions (`.github/workflows/ci.yml`). Everything is **hermetic** — the
network is mocked — so the same tests run identically on every OS and offline.

```
        UAT / user-journeys   ← few, high-confidence: 3 personas + CLI E2E
       integration (CLI/hook)  ← check / verify / install / MCP flows
      unit (decide/risk/policy ← many, fast, focused
      /supplychain/detectors/
      council/pinning/audit)
```

## What each layer covers

| Layer | Files | What it asserts | Type |
|---|---|---|---|
| **Unit** | `tests/test_decide.py`, `tests/test_harness.py` | risk scoring + tier boundaries; policy matching (incl. cross-platform paths + Windows commands); detectors; supply-chain (OSV mock, blocklist override, subshell, release-age); council consensus; descriptor pinning; audit hash-chain + tamper detection; config/env overrides | many, fast |
| **Integration** | `tests/test_journeys.py` (CLI E2E) | the installed `eldermind` console entrypoint blocks + writes a verifiable audit chain, via `python -m eldermind.cli` (cross-OS) | some |
| **UAT / journeys** | `tests/test_journeys.py` | three persona journeys end-to-end (below) + audit integrity across a journey | few |

## Personas under test (UAT)

| Persona | Config | Journey asserts |
|---|---|---|
| **Technical user** (dev + coding agent) | `operator` tier, supply-chain on | routine work allowed; `rm -rf /`, force-push, `curl\|bash` blocked; malicious `axios@1.14.1` blocked (ASI04); secrets `read .env` escalated to **block** (operator) |
| **Knowledge worker** (prototyping) | `practitioner` (default), supply-chain on | clean `pip install requests` allowed (+ hygiene tip); `prototype.py` write allowed; compromised `litellm==1.82.7` blocked; `.env` edit → **ask** with a plain-language preview |
| **Back-office non-tech** | `explorer` tier; + `observe` onboarding | `read .env` relaxed to **warn** (low friction) but the preview still teaches *why*; `rm -rf /` **never** relaxed (stays block); Windows `Remove-Item -Recurse -Force` blocks; `C:\…\.aws\credentials` recognised; observe mode never blocks but records `observed_verdict` |

These journeys are what caught the `write-agent-or-ci-config` over-match bug
(a glob basename `**` matched every file write) before it shipped — the reason
UAT sits above the unit layer.

## Cross-platform coverage

- **Logic is host-independent**: the gate matches command/path *patterns*, so a
  Windows PowerShell command or `C:\…` path is exercised on any runner (and is).
- **The OS matrix** additionally proves the wheel installs and the CLI runs
  natively on macOS, Windows, and Linux (the regression + UAT jobs run on all three).

## CI jobs (`.github/workflows/ci.yml`)

| Job | Runners | Runs |
|---|---|---|
| `regression` | ubuntu · macos · windows × py3.11/3.12/3.13 | full unit + integration suite |
| `user-journeys` | ubuntu · macos · windows | the persona UAT + CLI E2E |
| `offline-determinism` | ubuntu | same input → identical decision + id |
| `honesty` | ubuntu | no overclaims; correct OWASP-2026 taxonomy; threat model present |
| `build` | ubuntu | wheel builds with `policy.yaml` + `blocklist.json` bundled |

## Run it locally

```bash
pip install -e ".[mcp,dev]"
pytest tests/ -q                      # everything (regression + UAT)
pytest tests/test_journeys.py -v      # just the persona journeys
```

## Coverage targets & gaps

- **Covered:** every policy rule, every verdict path, every tier, both OS command
  families, the supply-chain tiers, the audit chain, and all three personas.
- **Deliberately not unit-tested** (would need live services / are out of scope):
  real OSV/deps.dev network calls (mocked), real MCP client round-trips (the server
  imports + tool signatures are checked), and live in-IDE hook execution on each
  agent (the translators are tested against doc-accurate event shapes; true
  in-Kiro/OpenCode runs remain manual until those harnesses are scriptable in CI).

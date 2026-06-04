# Start here

Pick your path. Elder Mind is a **local-first governance harness** that checks
your coding agent's actions *before* they run — on your machine, with your model.

| I am a… | Go to | Time |
|---|---|---|
| **Developer** who wants protection now | [Quick start](#quick-start) — install, see a block, done | 2 min |
| **Developer** who wants to understand first | [README](README.md) → [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 15 min |
| **Team lead** rolling agents out to a team | [Team rollout](#team-lead) — one `policy.yaml` everyone shares | 20 min |
| **Security / risk owner** | [`docs/STANDARDS-MAP.md`](docs/STANDARDS-MAP.md) + [`THREAT_MODEL.md`](THREAT_MODEL.md) + [`docs/COUNCIL.md`](docs/COUNCIL.md) | 30 min |
| **Non-technical operator** trying agents | [Gentle start](#non-technical-operator) — low friction, learn as you go | 10 min |
| **Just want to read it on paper** | Branded PDFs in [`docs/pdf/`](docs/pdf/) | — |

---

## Quick start
*(developer — the fast path)*

```bash
# needs Python 3.11+
git clone https://github.com/Cyber-Elders/elder-mind-harness && cd elder-mind-harness
pipx install .                # from source (pre-release) — or: pip install .
eldermind init claude-code    # guided setup; or opencode | kiro | cursor
```

Then try a dangerous command and watch it get stopped:

```bash
echo '{"action":"bash","target":"git push --force origin main"}' | eldermind check
# ⛔ block · risk 16/25 · OWASP ASI02 Tool Misuse · decision EM-…
eldermind verify     # the audit chain is intact
```

Pick a **tier** during `init` (or in `.eldermind/config.toml`):
`explorer` (low friction) · **`practitioner`** (default) · `governed` · `operator` (strictest).

---

## Team lead
*(consistent governance across a team)*

1. `eldermind init <tool> --supplychain` in a shared repo, then commit `.eldermind/policy.yaml` — every teammate's agent now obeys the same rules.
2. Set the tier in `.eldermind/config.toml` (e.g. `governed`) and turn on supply-chain protection.
3. The append-only, hash-chained `.eldermind/audit.jsonl` (`eldermind verify`, `eldermind summary`) gives you reviewable evidence of what agents did. `verify` catches accidental/partial edits and prints the chain head — record that head outside the repo if you need to detect a deliberate full rewrite (see [`THREAT_MODEL.md`](THREAT_MODEL.md)).
4. Editing agent/CI config (`.claude/`, `.vscode/`, `.github/workflows/`) and secrets files is gated by default — see [`docs/STANDARDS-MAP.md`](docs/STANDARDS-MAP.md).

---

## Non-technical operator
*(you've started using an AI agent and don't want to break things)*

1. **The easiest way — let your agent do it.** Tell your AI assistant: *"Please install the Elder Mind governance harness and walk me through the setup."* Your AI assistant can install it for you and explain each choice as it goes — you don't need to touch a command line.
2. Ask for the **`explorer`** tier — it warns instead of constantly interrupting, but **never** lets through the truly dangerous stuff. (Doing it yourself? `eldermind init <your tool>`.)
3. Prefer to just watch first? Ask your agent to *"set up Elder Mind in observe mode"* — it logs what it *would* have done, but blocks nothing.
4. Every time something is flagged you get a **plain-language reason** ("This can execute remote code on your machine") — read it; that's how you learn safe agent habits.
5. When in doubt, ask your agent to explain: *"why did Elder Mind flag that?"* — it can call `eldermind explain <decision-id>`.

---

## What it does NOT do
Elder Mind is honest about its edges — it's not a prompt-injection classifier, an OS sandbox, a full dependency scanner, or a multi-agent monitor. See [`THREAT_MODEL.md`](THREAT_MODEL.md) and the "Pairs with" section of the [README](README.md#pairs-with-defense-in-depth).

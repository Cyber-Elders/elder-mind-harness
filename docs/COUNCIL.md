# The Cyber Elder AI Council

> A second opinion before the agent acts — delivered by *your own* models, not ours.

The **Council** is Elder Mind's optional multi-model review for high-risk actions.
When the deterministic gate isn't sure enough to allow but the call is too
nuanced to hard-block, it can convene a council: one or more language models
each judge the proposed action independently, and their votes are combined under
a fixed consensus rule. It is **bring-your-own-LLM** — Elder Mind ships **no API
keys and makes no cloud calls of its own**. The council reasons with the model
your coding agent already uses (and any extra models you choose to route to).

## Why a council at all

A single deterministic gate is excellent at the clear cases — `rm -rf /` is
always block, `ls` is always allow. The hard cases live in the middle: an action
that *might* be fine in context. Three failure modes the council guards against:

- **One model's blind spot.** A single model can rationalize a bad action or
  flag a benign one. Independent judges with a consensus rule dampen both.
- **Goal hijack (OWASP ASI01).** If untrusted content has quietly steered the
  agent, asking "is this action consistent with the stated goal?" can catch it —
  a deterministic pattern can't. **Caveat:** with the *default* single-model
  config this is the *same* model that proposed the action grading its own
  homework (and any injection in its context travels into the review prompt), so
  it acts mainly as a structured pause, not an independent check. Genuine
  independence requires configuring a *different* model (see Configuring models).
- **Reflexive approval.** Routing a high-risk call through a structured review
  (instead of a one-tap "allow") slows the human down at exactly the right moment.

## Where it sits

```
tool call ─► gate (policy + risk + detectors)
                 │
        allow / warn ─────────────────► proceed
                 │
            ask  ─► COUNCIL (optional) ─► proceed / block (by consensus)
                 │                         │
            block ───────────────────────► stop
```

The council only engages on **`ask`-tier** decisions (risk score ~10–19). Hard
blocks stay hard; allows stay fast. If no model is configured, the `ask` simply
falls back to **asking the human** — the council never becomes a hard dependency.

> **It's an advisory path, by design.** The council is exposed as the
> `council_review` MCP tool, which the host agent *chooses* to call on an `ask`
> verdict — it is **not** wired into the deterministic hard-gate hook (which only
> ever allows/warns/asks/blocks). So the council can strengthen an `ask` into a
> considered decision, but the hard gate's behaviour does not depend on it.

## How it works (BYO-LLM)

1. The gate produces an `ask` verdict with its reasoning (rule, OWASP tag, risk score, plain-language preview).
2. The host agent calls the `council_review` MCP tool, which returns a **structured deliberation task**: the action, the target, the risk, and a clear instruction — *"vote PROCEED or BLOCK, with a one-sentence justification."*
3. The host agent runs that prompt with **its own model**. If you've configured extra models (see below), each one votes.
4. Votes are combined by a **consensus rule**:
   - **Destructive / irreversible action** (delete, force-push, overwrite, …) → **unanimous to proceed**. Any single BLOCK vote stops it.
   - **Otherwise** → **simple majority**.
   - **Tie or any abstention** → **BLOCK** (conservative default).
5. The outcome is written to the hash-chained audit log like any other decision.

Because the deliberation runs in *your* environment with *your* models, the
council's quality scales with the models you give it — and nothing leaves your
machine that wouldn't already leave it through your coding agent.

## Configuring models

By default the council uses the host agent's single lead model. If you route
across several models, list them in `.eldermind/config.toml`:

```toml
[council]
# empty = use the host agent's own model. Add names if you route across models.
models = ["claude-sonnet", "a-local-ollama-model", "another-provider-model"]
```

More models = more independent perspectives = a stronger consensus signal, at
the cost of more calls per high-risk decision. Two or three diverse models is
usually the sweet spot; one is fine.

## What the council is — and is not

| It is | It is not |
|---|---|
| A second opinion on **high-risk** actions | A filter on every tool call (that's the deterministic gate) |
| Powered by **your** models (BYO-LLM) | A service that ships or requires API keys |
| A consensus over independent votes | A single model's say-so |
| Conservative on ties (defaults to block) | A way to *weaken* the gate — it can only escalate an `ask`, never relax a hard block |
| Fully audited and local | A cloud control plane or multi-agent runtime |

## Standards mapping

The council is Elder Mind's main lever on **OWASP ASI01 (Agent Goal Hijack)** —
a class a deterministic command-pattern gate can't detect on its own — and forms
the human-in-the-loop / escalation part of the **NIST AI RMF MANAGE** function.
See [`STANDARDS-MAP.md`](STANDARDS-MAP.md).

## Try it

With the MCP server running (`eldermind serve`), an MCP-capable agent can call:

```
council_review(action="bash", target="git push --force origin main",
               risk={"score": 16, "tier": "elevated_review"},
               reason="Matches 'git-force-push-protected' (ASI02 Tool Misuse)")
```

…and receive the deliberation task to run with its own model(s), then apply the
consensus rule to decide.

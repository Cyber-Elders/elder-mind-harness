# The Elder Mind idea

> Why "Elder Mind", why a "council", and how the pieces fit.

## The metaphor

For as long as people have made consequential decisions, they've leaned on a
**council of elders** — people whose judgment, earned over time, is consulted
*before* an irreversible act, not after the damage. The elder's role isn't to
do the work; it's to pause it at the right moment and ask: *is this wise? is it
reversible? who does it affect? is there a safer way?*

A coding agent today has enormous reach — it can run shell commands, rewrite
files, install dependencies, call tools, and act on your behalf in seconds. What
it usually lacks is that pause. **Elder Mind gives the agent an elder**: a calm,
consistent check at the exact moment of action.

That's the whole idea — *calm authority at the moment of action*.

## The three layers

The name maps to three concrete things, from maker to mechanism:

| Layer | What it is |
|---|---|
| **Cyber Elders** | The maker — the people/organisation behind the work (© Cyber Elders Pty Ltd). The "elders" whose security judgment is encoded into the tools. |
| **Elder Mind** | The *governing mind* — the methodology and principles for governing agentic work: a small set of standards-grounded, honest rules about what an agent should pause on. The accumulated judgment, made legible. |
| **The Governance Harness** | The *runtime* — this repository. The harness that puts Elder Mind into the loop of your coding agent: a deterministic pre-tool-use gate, plus supply-chain checks, threat detectors, and the council. |

So: **Cyber Elders** *make it* · **Elder Mind** *is the judgment* · **the harness**
*applies it, locally, at the tool-call boundary.*

## The council

When a decision is genuinely uncertain — not obviously safe, not obviously
catastrophic — one elder's opinion isn't enough. That's when the harness can
convene a **council**: several models weigh in independently and a consensus
rule decides. Crucially, it's **your** council — it runs on the models *you*
already use; Elder Mind ships no model and no keys. The full design is in
[`COUNCIL.md`](COUNCIL.md).

The council is the metaphor made literal: a small group of advisors, consulted
before the act, conservative when they disagree.

## The philosophy (what makes it different)

Four commitments shape every design decision in this repo:

1. **Govern the action.** Most AI-safety tooling filters *text* (prompts and
   outputs). Elder Mind governs the *action* — the moment the agent is about to
   run a command, touch a secret, install a package, or push to a branch. That's
   where irreversible harm actually happens.
2. **Teach the operator.** Every block is a teachable moment, not an opaque
   "denied". It names the consequence in plain language ("this can execute remote
   code") and maps to a recognised standard (OWASP Agentic / NIST AI RMF). You
   get safer *and* you learn why.
3. **Keep it local.** The decision is deterministic and runs on your machine —
   no cloud control plane, no telemetry, no model in the verdict path. Same input,
   same decision, reproducible, offline. Your workflow is yours.
4. **Be honest about the boundary.** Elder Mind says clearly what it does *not*
   do — it's not a prompt-injection classifier, an OS sandbox, or a multi-agent
   monitor. Ceding those openly is what makes the things it *does* claim credible.
   (See [`../THREAT_MODEL.md`](../THREAT_MODEL.md).)

## Who it's for

Anyone whose agent can cause real harm but who doesn't have an enterprise
security team behind them: the solo developer, the team lead rolling agents out,
the security-conscious shop, the non-technical operator learning to build with
agents. The [START-HERE](../START-HERE.md) router points each to the right path.

## In one sentence

> **Elder Mind is the pause a wise elder would insist on — a local, deterministic,
> honest check at the moment your coding agent is about to act.**

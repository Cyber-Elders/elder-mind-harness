"""
Council review — BYO-LLM multi-model deliberation for high-risk decisions.

Elder Mind ships NO model clients and NO API keys. The council uses the
*user's own* LLM: when the host agent (Claude Code, Kiro, OpenCode, …) calls
the `council_review` MCP tool, this module returns a structured deliberation
task, and the host agent's own lead model performs the reasoning. If the user
routes across several models (configured in .eldermind/config.toml), each model
casts a vote and `tally()` applies the consensus rule. With no model available,
the caller degrades to a plain human "ask".

This keeps the council local to the user's setup and cloud-free on our side —
the user's existing model access is the only LLM dependency.
"""

from __future__ import annotations

from dataclasses import dataclass

# Verbs that make an action irreversible/destructive -> require unanimity to proceed.
_DESTRUCTIVE_HINTS = ("rm ", "drop ", "--force", "delete", "destroy", "truncate", "overwrite")


@dataclass(frozen=True)
class Vote:
    model: str
    vote: str  # "proceed" | "block"
    reason: str


def build_review(action: str, target: str, risk: dict, reason: str, models: list[str] | None = None) -> dict:
    """Return a deliberation task for the host agent's model(s) to execute.

    The host agent reads `prompt`, reasons with its own model (once per entry in
    `models`, or once with its lead model if `models` is empty), and reports
    votes back via `tally()` semantics.
    """
    models = models or []
    destructive = any(h in (target or "").lower() for h in _DESTRUCTIVE_HINTS)
    consensus = "unanimous_to_proceed" if destructive else "majority"
    prompt = (
        "You are a governance council member reviewing a proposed coding-agent action.\n"
        f"ACTION: {action}\nTARGET: {target}\n"
        f"RISK: score {risk.get('score')}/25 ({risk.get('level')}), tier {risk.get('tier')}\n"
        f"GATE REASON: {reason}\n\n"
        "Decide whether to PROCEED or BLOCK. Consider: is this reversible? does it touch "
        "secrets, production, or destructive operations? is there a safer alternative?\n"
        "Respond with: vote=PROCEED|BLOCK and a one-sentence justification."
    )
    return {
        "prompt": prompt,
        "models": models,                 # empty -> host's own lead model
        "rounds": max(1, len(models)),
        "consensus_rule": consensus,      # how tally() will combine the votes
        "destructive": destructive,
        "instructions": (
            "Run the prompt once per model (or once with your lead model if the list is empty), "
            "collect the votes, then apply the consensus rule via the gate's tally semantics: "
            f"'{consensus}'. On a tie or any abstention, default to BLOCK (conservative)."
        ),
    }


def tally(votes: list[Vote] | list[dict], consensus_rule: str = "majority") -> dict:
    """Combine council votes into a final verdict.

    unanimous_to_proceed: ALL must vote proceed, else block.
    majority: more proceed than block, else block (ties -> block, conservative).
    """
    norm: list[Vote] = [
        v if isinstance(v, Vote) else Vote(v.get("model", "?"), v.get("vote", "block"), v.get("reason", ""))
        for v in votes
    ]
    if not norm:
        return {"verdict": "block", "rationale": "no votes — conservative default", "votes": []}

    proceed = [v for v in norm if v.vote.lower() == "proceed"]
    block = [v for v in norm if v.vote.lower() != "proceed"]

    if consensus_rule == "unanimous_to_proceed":
        ok = len(block) == 0
    else:  # majority
        ok = len(proceed) > len(block)

    return {
        "verdict": "proceed" if ok else "block",
        "rationale": f"{len(proceed)} proceed / {len(block)} block under '{consensus_rule}'",
        "votes": [{"model": v.model, "vote": v.vote, "reason": v.reason} for v in norm],
    }

"""
MCP server (FastMCP) — the ADVISORY path.

Exposes governance tools any MCP-capable harness (Claude Code, OpenCode, Kiro,
Cursor, ...) can call. This path is *advisory*: an agent may call govern_check
and then ignore the result. Hard enforcement lives in the per-harness pre-tool
hook (see adapters/), which shells out to `eldermind check`.

Requires the optional dependency: pip install 'eldermind[mcp]'
"""

from __future__ import annotations

from .audit import record, summary
from .config import load_config
from .council import build_review
from .gate import evaluate

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "MCP server requires the [mcp] extra: pip install 'eldermind[mcp]'"
    ) from exc

mcp = FastMCP("eldermind")


@mcp.tool()
def govern_check(action: str, target: str, context: dict | None = None) -> dict:
    """Evaluate a proposed tool call against the governance policy.

    ADVISORY ONLY — returns a verdict (allow/warn/ask/block) with an
    OWASP-mapped reason and a deterministic decision_id (plus a dynamic
    supply-chain result when enabled). Does not block; the calling agent
    decides whether to honour it. For hard enforcement, install the
    pre-tool-use hook (`eldermind init <tool>`).

    Args:
        action: tool name (e.g. "bash", "edit", "read").
        target: the tool's primary argument (command string or file path).
        context: optional metadata (cwd, agent, risk_tier).
    """
    d = evaluate(action=action, target=target, context=context or {})
    try:
        record(d, outcome="advised", context=context or {})
    except OSError:
        pass
    return d


@mcp.tool()
def council_review(action: str, target: str, risk: dict | None = None, reason: str = "") -> dict:
    """Request multi-model 'council' review of a high-risk action — BYO-LLM.

    Returns a structured deliberation task for YOUR model(s) to run: read the
    `prompt`, reason with your own lead model (once per configured model, or
    once if none are configured), then combine the votes per `consensus_rule`
    (on a tie or abstention, BLOCK). Elder Mind ships no model and no keys —
    the council uses your agent's own LLM. Use this when a verdict is "ask".
    """
    cfg = load_config()
    return build_review(action=action, target=target, risk=risk or {}, reason=reason, models=cfg.council_models)


@mcp.tool()
def scan(command_or_lockfile: str) -> dict:
    """Supply-chain check (OSV) for an install command or lockfile path.

    e.g. "npm install axios@1.14.1" or "pip install litellm==1.82.7", or a path
    to package-lock.json / requirements.txt / Cargo.lock. Uses the OSV.dev API
    (falls back to a bundled blocklist offline).
    """
    import os

    from .supplychain import scan_command, scan_lockfile
    if os.path.isfile(command_or_lockfile):
        return scan_lockfile(command_or_lockfile)
    results = scan_command(command_or_lockfile)
    return {"results": [
        {"package": r.package.name, "version": r.package.version, "ecosystem": r.package.ecosystem,
         "status": r.status, "detail": r.detail, "source": r.source}
        for r in results
    ]}


@mcp.tool()
def audit_log(action: str, target: str, outcome: str, reasoning: str = "") -> dict:
    """Record an action the agent took, for the audit trail.

    Use after performing a sensitive action so the trail reflects reality.
    """
    pseudo = {
        "decision_id": None,
        "verdict": "logged",
        "rule_id": None,
        "asi": None,
        "risk": {},
        "reason": reasoning or f"agent-reported: {action} {target}",
    }
    record(pseudo, outcome=outcome, context={"action": action, "target": target})
    return {"recorded": True}


@mcp.tool()
def audit_summary() -> dict:
    """Aggregate audit metrics (NIST AI RMF MEASURE)."""
    return summary()


def run() -> None:
    """Run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    run()

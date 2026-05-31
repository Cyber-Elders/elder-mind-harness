"""
Orchestration layer — combines the deterministic gate with the optional,
network-touching supply-chain check.

`decide()` (decide.py) stays pure and offline: policy + risk + regex detectors.
`evaluate()` wraps it and, ONLY when supply-chain protection is enabled in
config, additionally runs the dynamic OSV check on package-install commands and
escalates the verdict. This separation keeps the core gate's determinism /
offline guarantee intact and isolates the one feature that may hit the network.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import supplychain
from .config import Config, load_config
from .decide import decide
from .policy import ACTION_SEVERITY, Policy

_SHELL_TOOLS = {"bash", "shell", "powershell", "pwsh", "cmd"}
_STATUS_VERDICT = {"malicious": "block", "vulnerable": "ask"}

# Governance tiers change strictness deterministically (single lookup on the
# computed verdict — never chained). explorer relaxes friction but NEVER
# relaxes a hard block; operator is maximally strict.
_TIER_ADJUST = {
    "explorer": {"ask": "warn"},                    # low friction; block still blocks
    "practitioner": {},                             # sensible default (knowledge worker)
    "governed": {"warn": "ask"},                    # stricter
    "operator": {"warn": "ask", "ask": "block"},    # strictest
}


def _apply_tier(verdict: str, tier: str) -> str:
    return _TIER_ADJUST.get(tier, {}).get(verdict, verdict)


def _more_severe(a: str, b: str) -> str:
    return a if ACTION_SEVERITY.get(a, 0) >= ACTION_SEVERITY.get(b, 0) else b


def evaluate(
    action: str,
    target: str,
    context: dict | None = None,
    policy: Policy | str | Path | None = None,
    config: Config | None = None,
) -> dict:
    """Deterministic decision + optional dynamic supply-chain escalation."""
    decision = decide(action=action, target=target, context=context or {}, policy=policy).to_dict()
    cfg = config or load_config()

    if cfg.supplychain_enabled and action.lower() in _SHELL_TOOLS:
        results = supplychain.scan_command(target)
        w = supplychain.worst(results)
        if w is not None and w.status in _STATUS_VERDICT:
            sc_verdict = _STATUS_VERDICT[w.status]
            decision["verdict"] = _more_severe(decision["verdict"], sc_verdict)
            decision["suggest"] = "ask" if decision["verdict"] in ("ask", "block") else decision["verdict"]
            ver = w.package.version or "unpinned"
            decision["reason"] += (
                f"; supply-chain: {w.package.name}@{ver} {w.status.upper()} "
                f"(ASI04 Agentic Supply Chain; {w.detail})"
            )
            decision["asi"] = decision.get("asi") or "ASI04"
            decision["preview"] = "This may install a known-compromised or risky dependency."
        if w is not None:
            decision["supplychain"] = {
                "status": w.status,
                "package": w.package.name,
                "version": w.package.version,
                "ecosystem": w.package.ecosystem,
                "detail": w.detail,
                "source": w.source,
            }
            # Low-noise hygiene nudge on installs that aren't outright bad
            # (OpenSSF guidance: pin + commit lockfile + npm ci / min release age).
            if w.status in ("clean", "unknown"):
                decision["reason"] += " · tip: pin the version + commit your lockfile (npm ci / uv lock)"

    # Governance tier adjusts strictness (deterministic).
    adjusted = _apply_tier(decision["verdict"], cfg.tier)
    if adjusted != decision["verdict"]:
        decision["reason"] += f" · tier '{cfg.tier}': {decision['verdict']}→{adjusted}"
        decision["verdict"] = adjusted
        decision["suggest"] = "ask" if adjusted in ("ask", "block") else adjusted

    # Observe mode: never block — log what WOULD have happened, then proceed.
    if cfg.mode == "observe" and decision["verdict"] in ("ask", "block"):
        decision["observed_verdict"] = decision["verdict"]
        decision["verdict"] = "warn"
        decision["reason"] = f"[observe] would {decision['observed_verdict']} — {decision['reason']}"

    return decision


def evaluate_exit_code(decision: dict) -> int:
    """0 for allow/warn (proceed), 2 for ask/block (stop and surface)."""
    return 0 if decision.get("verdict") in ("allow", "warn") else 2


def evaluate_json(request: str | dict, policy=None, config: Config | None = None) -> dict:
    if isinstance(request, str):
        request = json.loads(request)
    return evaluate(
        action=request.get("action", ""),
        target=request.get("target", ""),
        context=request.get("context", {}),
        policy=policy,
        config=config,
    )

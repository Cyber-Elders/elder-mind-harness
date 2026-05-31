# SPDX-License-Identifier: Apache-2.0
"""
decide() — the single entry point.

Glues: policy match -> Risk Engine score -> escalation tier -> verdict.

Deterministic and offline by construction. The returned Decision (including
its decision_id, which is a content hash) depends only on the inputs and the
policy — never on wall-clock time, randomness, or the network. The audit
writer adds the event timestamp; the decision itself does not carry one.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path

from . import detectors as _detectors
from .policy import ACTION_SEVERITY, Policy, PolicyError, load_policy, match
from .risk_engine import EscalationRouter, RiskAssessor

# Escalation tier -> the verdict the score alone would produce. The council_*
# tiers map to "ask": when a model is configured, the host agent runs council
# review (see council.py); otherwise the human is asked.
TIER_TO_VERDICT = {
    "auto_approve": "allow",
    "notify_after": "warn",
    "review": "ask",
    "elevated_review": "ask",
    "block_critical": "block",
}

_SEVERITY_TO_ACTION = {v: k for k, v in ACTION_SEVERITY.items()}


@dataclass(frozen=True)
class Decision:
    """The verdict returned for one proposed tool call."""

    verdict: str  # allow | warn | ask | block  (load-bearing)
    reason: str
    rule_id: str | None
    asi: str | None
    risk: dict  # {impact, likelihood, score, level, tier}
    suggest: str  # recommended human interaction if proceeding anyway
    decision_id: str  # content hash, deterministic
    policy_version: str
    detectors: list = field(default_factory=list)  # heuristic findings (deterministic)
    preview: str = ""  # plain-language consequence, for ask/block prompts

    def to_dict(self) -> dict:
        return asdict(self)

    def exit_code(self) -> int:
        """0 for allow/warn (proceed), 2 for ask/block (stop and surface)."""
        return 0 if self.verdict in ("allow", "warn") else 2


def _more_severe(a: str, b: str) -> str:
    """Return whichever action is more restrictive."""
    return a if ACTION_SEVERITY[a] >= ACTION_SEVERITY[b] else b


def _decision_id(action: str, target: str, verdict: str, score: int, version: str) -> str:
    """Deterministic content-addressed id. Same decision -> same id, offline."""
    payload = f"{version}|{action}|{target}|{verdict}|{score}".encode()
    return "EM-" + hashlib.sha256(payload).hexdigest()[:12]


@lru_cache(maxsize=8)
def _cached_policy(path_str: str, mtime: float) -> Policy:
    # mtime is part of the cache key so edits to the file are picked up.
    return load_policy(path_str)


def _load(policy: Policy | str | Path | None) -> Policy:
    if isinstance(policy, Policy):
        return policy
    if policy is None:
        policy = default_policy_path()
    path = Path(policy)
    return _cached_policy(str(path), path.stat().st_mtime if path.exists() else 0.0)


def default_policy_path() -> Path:
    """Resolve the policy file: project .eldermind/policy.yaml, else bundled default."""
    project = Path.cwd() / ".eldermind" / "policy.yaml"
    if project.exists():
        return project
    return Path(__file__).resolve().parent / "policy.yaml"


def decide(
    action: str,
    target: str,
    context: dict | None = None,
    policy: Policy | str | Path | None = None,
) -> Decision:
    """Score a proposed tool call and return a Decision.

    Args:
        action: the tool name (e.g. "bash", "edit", "read").
        target: the tool's primary argument (command string, file path).
        context: optional metadata (cwd, agent, risk_tier) — recorded, not required.
        policy: a Policy, a path to one, or None to auto-resolve.
    """
    context = context or {}
    try:
        pol = _load(policy)
    except PolicyError:
        # Fail-safe: if the policy can't load, ask the human. on_error default.
        return Decision(
            verdict="ask",
            reason="policy could not be loaded; failing safe to human review",
            rule_id=None,
            asi=None,
            risk={"impact": 0, "likelihood": 0, "score": 0, "level": "unknown", "tier": "n/a"},
            suggest="ask",
            decision_id=_decision_id(action, target, "ask", 0, "error"),
            policy_version="error",
        )

    # Deterministic heuristic detector pass (pure regex, offline).
    findings = _detectors.scan(target)
    det_worst = _detectors.worst_finding(findings)
    det_verdict = det_worst.suggested_verdict if det_worst else "allow"
    det_list = [
        {"name": f.name, "severity": f.severity, "mitre": f.mitre, "description": f.description}
        for f in findings
    ]

    rule = match(pol, action, target)

    if rule is None:
        verdict = _more_severe(pol.unmatched, det_verdict)
        reason = "no policy rule matched; default action applied"
        if det_worst:
            reason = f"Heuristic detector '{det_worst.name}' ({det_worst.mitre}); no policy rule matched"
        return Decision(
            verdict=verdict,
            reason=reason,
            rule_id=None,
            asi=("ASI02" if det_worst else None),
            risk={"impact": 1, "likelihood": 1, "score": 1, "level": "low", "tier": "auto_approve"},
            suggest=_suggest_for(verdict),
            decision_id=_decision_id(action, target, verdict, 1, pol.version),
            policy_version=pol.version,
            detectors=det_list,
            preview=_preview_for("ASI02") if det_worst else "",
        )

    assessment = RiskAssessor().assess(rule.impact, rule.likelihood)
    escalation = EscalationRouter().route(assessment)
    tier_verdict = TIER_TO_VERDICT[escalation.action]

    # Rule action is the floor; the tier and any detector may escalate, never relax below.
    verdict = _more_severe(_more_severe(rule.action, tier_verdict), det_verdict)

    asi_label = f"{rule.asi} {_ASI_NAMES.get(rule.asi, '')}".strip()
    reason = f"Matches rule '{rule.id}' ({asi_label})" if rule.asi else f"Matches rule '{rule.id}'"
    if det_worst:
        reason += f"; heuristic detector '{det_worst.name}' ({det_worst.mitre})"

    return Decision(
        verdict=verdict,
        reason=reason,
        rule_id=rule.id,
        asi=rule.asi or None,
        risk={
            "impact": assessment.impact,
            "likelihood": assessment.likelihood,
            "score": assessment.score,
            "level": assessment.level,
            "tier": escalation.action,
        },
        suggest=_suggest_for(verdict),
        decision_id=_decision_id(action, target, verdict, assessment.score, pol.version),
        policy_version=pol.version,
        detectors=det_list,
        preview=_preview_for(rule.asi),
    )


def _suggest_for(verdict: str) -> str:
    """Recommended human interaction if proceeding despite the verdict."""
    # block/ask both invite a human confirm/override path.
    return "ask" if verdict in ("block", "ask") else verdict


# Plain-language consequence per ASI — for human-readable ask/block prompts.
# (The assessment's top UX recommendation: tell the operator what's at stake,
# not just the rule id.)
_PREVIEW = {
    "ASI01": "Untrusted input may be steering the agent's goal — check this is what you asked for.",
    "ASI02": "This tool use can damage your system or exfiltrate data.",
    "ASI03": "This touches credentials, keys, or execution-controlling config.",
    "ASI04": "This may install a known-compromised or risky dependency.",
    "ASI05": "This can execute unexpected or remote code on your machine.",
}


def _preview_for(asi: str | None) -> str:
    return _PREVIEW.get(asi or "", "")


# OWASP Top 10 for Agentic Applications (2026), final 1.0 — official titles.
# Source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
# Do NOT edit to match the legacy LLM-Top-10 reskin.
_ASI_NAMES = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


def decide_json(request: str | dict, policy: Policy | str | Path | None = None) -> dict:
    """Convenience: take a request dict/JSON-string, return the Decision dict."""
    if isinstance(request, str):
        request = json.loads(request)
    return decide(
        action=request.get("action", ""),
        target=request.get("target", ""),
        context=request.get("context", {}),
        policy=policy,
    ).to_dict()

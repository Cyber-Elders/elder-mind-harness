# SPDX-License-Identifier: Apache-2.0
"""
Risk Engine — deterministic Impact x Likelihood scoring + escalation routing.

Pure, offline, zero-dependency (stdlib only). No LLM, no network, no I/O.
Same input always produces the same score, tier, and reasoning.

This module only scores and routes; the caller decides what to do with the
result. There is no persistence, no async, and no model dependency in the
decision path — that is what makes every verdict reproducible and explainable.

Scoring:
    score = impact (1-5) x likelihood (1-5)  ->  1..25

Levels:
    low      1-4
    medium   5-9
    high     10-14
    critical 15-25
"""

from __future__ import annotations

from dataclasses import dataclass


def _clamp(value: int, low: int = 1, high: int = 5) -> int:
    """Clamp an int into [low, high]."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = low
    return max(low, min(high, value))


@dataclass(frozen=True)
class RiskAssessment:
    """Result of scoring a single proposed action."""

    impact: int  # 1-5
    likelihood: int  # 1-5
    score: int  # impact * likelihood, 1-25
    level: str  # low | medium | high | critical
    reasoning: str


@dataclass(frozen=True)
class EscalationDecision:
    """Where a RiskAssessment routes in the escalation model."""

    action: str  # auto_approve | notify_after | review | elevated_review | block_critical
    approver: str  # system | user
    timeout_minutes: int  # 0 (immediate), 60, 120, 240
    fallback: str  # approve | conservative_deny


class RiskAssessor:
    """Score and classify risk for a proposed change or action."""

    # (min_score, max_score) inclusive
    RISK_LEVELS = {
        "low": (1, 4),
        "medium": (5, 9),
        "high": (10, 14),
        "critical": (15, 25),
    }

    def classify_level(self, score: int) -> str:
        """Convert a numeric score into a level string."""
        for level, (lo, hi) in self.RISK_LEVELS.items():
            if lo <= score <= hi:
                return level
        # score below 1 -> low; above 25 -> critical (defensive)
        return "low" if score < 1 else "critical"

    def assess(
        self,
        impact: int,
        likelihood: int,
        reasoning: str = "",
    ) -> RiskAssessment:
        """Produce a RiskAssessment from impact and likelihood scores.

        Inputs are clamped to 1-5. The product is the score.
        """
        impact = _clamp(impact)
        likelihood = _clamp(likelihood)
        score = impact * likelihood
        level = self.classify_level(score)
        if not reasoning:
            reasoning = f"impact {impact} x likelihood {likelihood} = {score} ({level})"
        return RiskAssessment(
            impact=impact,
            likelihood=likelihood,
            score=score,
            level=level,
            reasoning=reasoning,
        )


class EscalationRouter:
    """Route a RiskAssessment to the correct approval tier.

    The review tiers route to multi-model "council" review when a model is
    available (see council.py); otherwise decide.py maps them to a human "ask".
    Tier names are stable so the council can slot in behind the same interface
    without changing the scoring contract.
    """

    # (max_score, action, approver, timeout_minutes, fallback)
    TIERS = [
        (4, "auto_approve", "system", 0, "approve"),
        (9, "notify_after", "system", 0, "approve"),
        (14, "review", "user", 60, "conservative_deny"),
        (19, "elevated_review", "user", 120, "conservative_deny"),
        (25, "block_critical", "user", 240, "conservative_deny"),
    ]

    def route(self, assessment: RiskAssessment) -> EscalationDecision:
        """Determine the escalation path based on the risk score."""
        score = max(1, min(25, assessment.score))
        for max_score, action, approver, timeout, fallback in self.TIERS:
            if score <= max_score:
                return EscalationDecision(
                    action=action,
                    approver=approver,
                    timeout_minutes=timeout,
                    fallback=fallback,
                )
        # Unreachable given clamping, but stay safe.
        _, action, approver, timeout, fallback = self.TIERS[-1]
        return EscalationDecision(action, approver, timeout, fallback)

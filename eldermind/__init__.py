"""Elder Mind — a local-first agentic governance harness for coding agents.

Deterministic pre-tool-use gate (impact x likelihood -> escalation tier),
dynamic supply-chain checks, regex threat detectors, and optional BYO-LLM
"council" review. Local, offline-capable, OWASP-Agentic-aware,
NIST-AI-RMF-aligned.
"""

from .decide import Decision, decide, decide_json
from .risk_engine import (
    EscalationDecision,
    EscalationRouter,
    RiskAssessment,
    RiskAssessor,
)

__version__ = "0.1.0"

__all__ = [
    "decide",
    "decide_json",
    "Decision",
    "RiskAssessor",
    "RiskAssessment",
    "EscalationRouter",
    "EscalationDecision",
    "__version__",
]

"""
Audit trail — append-only JSONL.

One JSON object per line in .eldermind/audit.jsonl. No database, no Merkle
chain in v0.1 (a hash-chain can be added later without changing this
interface). The decision itself is deterministic (see decide.py); the audit
event additionally carries a wall-clock timestamp, which is the per-event
uniqueness the decision_id deliberately omits.

`summary()` provides the aggregate counts that back the NIST RMF "MEASURE"
claim — MEASURE means metrics over time, not just a raw log.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def audit_dir() -> Path:
    """Resolve the audit directory: $ELDERMIND_DIR or ./.eldermind."""
    override = os.environ.get("ELDERMIND_DIR")
    base = Path(override) if override else (Path.cwd() / ".eldermind")
    return base


def audit_path() -> Path:
    return audit_dir() / "audit.jsonl"


def record(decision: dict, outcome: str = "decided", context: dict | None = None) -> str:
    """Append one audit event. Returns the decision_id.

    `outcome` is what actually happened downstream ("decided", "allowed",
    "blocked", "overridden") — supplied by the caller/adapter when known.
    """
    path = audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "decision_id": decision.get("decision_id"),
        "verdict": decision.get("verdict"),
        "outcome": outcome,
        "rule_id": decision.get("rule_id"),
        "asi": decision.get("asi"),
        "score": (decision.get("risk") or {}).get("score"),
        "tier": (decision.get("risk") or {}).get("tier"),
        "reason": decision.get("reason"),
        "context": context or {},
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event["decision_id"] or ""


def read_events(path: str | Path | None = None) -> list[dict]:
    """Read all audit events (skips malformed lines)."""
    p = Path(path) if path else audit_path()
    if not p.exists():
        return []
    events = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def summary(path: str | Path | None = None) -> dict:
    """Aggregate metrics over the audit log — backs the NIST RMF MEASURE claim."""
    events = read_events(path)
    by_verdict: dict[str, int] = {}
    by_asi: dict[str, int] = {}
    high_risk = 0
    for e in events:
        v = e.get("verdict", "unknown")
        by_verdict[v] = by_verdict.get(v, 0) + 1
        asi = e.get("asi")
        if asi:
            by_asi[asi] = by_asi.get(asi, 0) + 1
        if (e.get("score") or 0) >= 10:
            high_risk += 1
    return {
        "total_events": len(events),
        "by_verdict": by_verdict,
        "by_asi": by_asi,
        "high_risk_calls": high_risk,
        "blocked": by_verdict.get("block", 0),
        "asked": by_verdict.get("ask", 0),
    }

# SPDX-License-Identifier: Apache-2.0
"""
Audit trail — append-only, hash-chained JSONL.

One JSON object per line in .eldermind/audit.jsonl. Each entry carries `prev`
(the previous entry's hash) and `hash` (sha256 over this entry incl. `prev`),
forming a hash chain: `verify()` detects accidental or partial edits —
altering, reordering, or dropping an entry without recomputing the chain.

IMPORTANT (honest scope): this is tamper-EVIDENT against careless edits, not
tamper-PROOF. An attacker (or a compromised agent) with write access to
`.eldermind/` can delete an entry and recompute the whole chain + `audit.head`,
and `verify()` would then pass. There is no external anchor here. To detect a
full rewrite, record the head hash off-box (`eldermind verify` prints it). See
THREAT_MODEL.md "Self-protection & audit integrity". No external service, no DB
— the chain is local. `audit.head` caches the latest hash for O(1) appends.

The decision itself is deterministic (see decide.py); the audit event adds a
wall-clock timestamp — the per-event uniqueness the decision_id omits.

`summary()` provides aggregate counts (NIST RMF "MEASURE" = metrics over time).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

_GENESIS = "EM-GENESIS"


def audit_dir() -> Path:
    """Resolve the audit directory: $ELDERMIND_DIR or ./.eldermind."""
    override = os.environ.get("ELDERMIND_DIR")
    base = Path(override) if override else (Path.cwd() / ".eldermind")
    return base


def audit_path() -> Path:
    return audit_dir() / "audit.jsonl"


def _head_path() -> Path:
    return audit_dir() / "audit.head"


def _entry_hash(event_without_hash: dict) -> str:
    """sha256 over the canonical event (which already includes `prev`)."""
    canonical = json.dumps(event_without_hash, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def _read_head() -> str:
    hp = _head_path()
    if hp.exists():
        try:
            h = hp.read_text(encoding="utf-8").strip()
            if h:
                return h
        except OSError:
            pass
    # fall back to the last line's hash, else genesis
    events = read_events()
    return events[-1].get("hash", _GENESIS) if events else _GENESIS


def head_hash() -> str:
    """Current chain head. Record this externally (out of `.eldermind/`) to
    detect a full-chain rewrite that local `verify()` alone cannot catch."""
    return _read_head()


def record(decision: dict, outcome: str = "decided", context: dict | None = None) -> str:
    """Append one hash-chained audit event. Returns the decision_id."""
    path = audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    prev = _read_head()
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
        "prev": prev,
    }
    event["hash"] = _entry_hash(event)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    try:
        _head_path().write_text(event["hash"], encoding="utf-8")
    except OSError:
        pass
    return event["decision_id"] or ""


def verify(path: str | Path | None = None) -> dict:
    """Walk the chain and confirm integrity. Returns
    {ok, entries, broken_at, reason}. broken_at is the 1-based line number of
    the first tampered/broken entry, or None when intact."""
    events = read_events(path)
    expected_prev = _GENESIS
    for i, e in enumerate(events, start=1):
        stored = e.get("hash")
        if stored is None:
            return {"ok": False, "entries": len(events), "broken_at": i,
                    "reason": "entry missing hash (pre-chain or stripped)"}
        recomputed = _entry_hash({k: v for k, v in e.items() if k != "hash"})
        if recomputed != stored:
            return {"ok": False, "entries": len(events), "broken_at": i,
                    "reason": "content hash mismatch (entry altered)"}
        if e.get("prev") != expected_prev:
            return {"ok": False, "entries": len(events), "broken_at": i,
                    "reason": "broken link (entry inserted/removed/reordered)"}
        expected_prev = stored
    return {"ok": True, "entries": len(events), "broken_at": None, "reason": "chain intact"}


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

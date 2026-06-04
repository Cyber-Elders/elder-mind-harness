# SPDX-License-Identifier: Apache-2.0
"""
Tool-descriptor pinning — catch MCP/tool "rug-pulls".

A tool a user approved can later change its name, description, JSON schema,
command, args, env, or server origin (Google SAIF flags deceptive/changed tool
descriptions as a material agentic risk). This module pins a hash of a tool's
descriptor on first sight (trust-on-first-use) and flags drift afterwards.

Deterministic and offline — just canonical hashing of the descriptor. State
lives in .eldermind/pins.json (or $ELDERMIND_DIR).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

# Fields that define a tool's identity/behaviour. Anything outside these
# (e.g. cosmetic ordering) is ignored so the hash is stable.
_PINNED_FIELDS = ("name", "description", "schema", "inputSchema", "command", "args", "env", "origin", "server")


def _dir() -> Path:
    override = os.environ.get("ELDERMIND_DIR")
    return Path(override) if override else (Path.cwd() / ".eldermind")


def pins_path() -> Path:
    return _dir() / "pins.json"


@dataclass(frozen=True)
class PinResult:
    status: str   # new | ok | changed
    name: str
    hash: str
    previous: str | None = None


def descriptor_hash(descriptor: dict) -> str:
    """Stable hash over the identity/behaviour fields, order-independent."""
    subset = {k: descriptor.get(k) for k in _PINNED_FIELDS if k in descriptor}
    canonical = json.dumps(subset, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()[:32]


def _load() -> dict:
    p = pins_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    p = pins_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def check(name: str, descriptor: dict, *, record_new: bool = True) -> PinResult:
    """Trust-on-first-use with drift detection.

      new     -> first time we've seen this tool; pinned (record_new) → allow + note
      ok      -> descriptor matches the pin
      changed -> descriptor differs from the pin → caller should ask/block
    """
    h = descriptor_hash(descriptor)
    pins = _load()
    entry = pins.get(name)
    if entry is None:
        if record_new:
            pins[name] = {"hash": h, "first_seen": True}
            _save(pins)
        return PinResult("new", name, h)
    if entry.get("hash") == h:
        return PinResult("ok", name, h)
    return PinResult("changed", name, h, previous=entry.get("hash"))


def list_pins() -> dict:
    return _load()


def reset(name: str) -> bool:
    """Forget a pin (re-trust on next sight). Returns True if one was removed."""
    pins = _load()
    if name in pins:
        del pins[name]
        _save(pins)
        return True
    return False

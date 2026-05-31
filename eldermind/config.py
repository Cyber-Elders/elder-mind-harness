# SPDX-License-Identifier: Apache-2.0
"""
Config loader — reads .eldermind/config.toml (stdlib tomllib, no dependency).

Supply-chain protection is OFF by default and turned on at install time (the
user is asked). This keeps a bare `eldermind check` fully offline/deterministic
unless the user opted in. Council models default to empty (use the host
agent's own model).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Config:
    supplychain_enabled: bool = False
    council_models: list[str] = field(default_factory=list)
    tier: str = "practitioner"
    mode: str = "enforce"  # enforce | observe (observe = log/warn, never block)
    min_release_age_days: int = 0  # >0 = flag installs of packages younger than this (OpenSSF)


def config_path() -> Path:
    override = os.environ.get("ELDERMIND_DIR")
    base = Path(override) if override else (Path.cwd() / ".eldermind")
    return base / "config.toml"


def _env_override(enabled: bool) -> bool:
    """ELDERMIND_SUPPLYCHAIN=1 forces on, =0 forces off, unset leaves as-is.
    Applies whether or not a config file exists (CI / tests / quick toggles)."""
    val = os.environ.get("ELDERMIND_SUPPLYCHAIN")
    if val == "1":
        return True
    if val == "0":
        return False
    return enabled


def load_config(path: str | Path | None = None) -> Config:
    p = Path(path) if path else config_path()
    data: dict = {}
    if p.exists():
        try:
            data = tomllib.loads(p.read_text())
        except (OSError, tomllib.TOMLDecodeError):
            data = {}
    sc = data.get("supplychain", {}) or {}
    council = data.get("council", {}) or {}
    gov = data.get("governance", {}) or {}
    mode = os.environ.get("ELDERMIND_MODE") or gov.get("mode", "enforce")
    try:
        age = int(os.environ.get("ELDERMIND_MIN_RELEASE_AGE") or sc.get("min_release_age_days", 0))
    except (TypeError, ValueError):
        age = 0
    return Config(
        supplychain_enabled=_env_override(bool(sc.get("enabled", False))),
        council_models=list(council.get("models", []) or []),
        tier=str(gov.get("tier", "practitioner")),
        mode="observe" if str(mode).lower() == "observe" else "enforce",
        min_release_age_days=max(0, age),
    )

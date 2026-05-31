"""
Policy loading and matching.

Loads a deterministic YAML ruleset and matches an incoming (tool, target)
against it, top-to-bottom, first match wins. A matched rule yields the
impact/likelihood inputs for the Risk Engine plus the OWASP ASI tag and an
action floor.

Deterministic by construction: regex + glob + integers. No expressions, no
plugins, no network. The only third-party dependency is PyYAML.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Action ordering — used to enforce the "rule action is a floor" rule.
# A higher index is more restrictive. The escalation tier may raise the
# action up this ladder but may never lower it below the rule's floor.
ACTION_SEVERITY = {"allow": 0, "warn": 1, "ask": 2, "block": 3}


@dataclass(frozen=True)
class Rule:
    """A single policy rule."""

    id: str
    asi: str
    impact: int
    likelihood: int
    action: str
    tools: tuple[str, ...]
    pattern: str | None = None  # regex against target
    target_glob: tuple[str, ...] = field(default_factory=tuple)
    description: str = ""


@dataclass(frozen=True)
class Policy:
    """A loaded ruleset plus defaults."""

    version: str
    unmatched: str  # action when nothing matches (default allow)
    on_error: str  # action when the gate itself errors (default ask)
    rules: tuple[Rule, ...]


class PolicyError(Exception):
    """Raised when a policy file is malformed."""


def _as_tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy.yaml file."""
    path = Path(path)
    if not path.exists():
        raise PolicyError(f"policy file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:  # pragma: no cover - passthrough
        raise PolicyError(f"invalid YAML in {path}: {exc}") from exc

    defaults = raw.get("defaults", {}) or {}
    unmatched = defaults.get("unmatched", "allow")
    on_error = defaults.get("on_error", "ask")

    rules: list[Rule] = []
    for i, r in enumerate(raw.get("rules", []) or []):
        try:
            match = r.get("match", {}) or {}
            rule = Rule(
                id=r["id"],
                asi=r.get("asi", ""),
                impact=int(r["impact"]),
                likelihood=int(r["likelihood"]),
                action=r["action"],
                tools=_as_tuple(match.get("tool")),
                pattern=match.get("pattern"),
                target_glob=_as_tuple(match.get("target_glob")),
                description=r.get("description", ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyError(f"rule #{i} is malformed: {exc}") from exc
        if rule.action not in ACTION_SEVERITY:
            raise PolicyError(
                f"rule '{rule.id}' has unknown action '{rule.action}'"
            )
        # Compile regex eagerly so a bad pattern fails at load, not at match.
        if rule.pattern is not None:
            try:
                re.compile(rule.pattern)
            except re.error as exc:
                raise PolicyError(
                    f"rule '{rule.id}' has invalid regex: {exc}"
                ) from exc
        rules.append(rule)

    return Policy(
        version=str(raw.get("version", "0")),
        unmatched=unmatched,
        on_error=on_error,
        rules=tuple(rules),
    )


def _tool_matches(rule: Rule, tool: str) -> bool:
    if not rule.tools:
        return True  # no tool constraint -> applies to all tools
    tool = (tool or "").lower()
    return tool in {t.lower() for t in rule.tools}


def _target_matches(rule: Rule, target: str) -> bool:
    target = target or ""
    has_constraint = bool(rule.pattern) or bool(rule.target_glob)
    if not has_constraint:
        return True  # tool-only rule
    if rule.pattern is not None and re.search(rule.pattern, target):
        return True
    for glob in rule.target_glob:
        # Match both the full path and the basename so '**/.env' and '.env' work.
        if fnmatch.fnmatch(target, glob) or fnmatch.fnmatch(
            Path(target).name, Path(glob).name
        ):
            return True
    return False


def match(policy: Policy, tool: str, target: str) -> Rule | None:
    """Return the first rule that matches (tool, target), or None."""
    for rule in policy.rules:
        if _tool_matches(rule, tool) and _target_matches(rule, target):
            return rule
    return None

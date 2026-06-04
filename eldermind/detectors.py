# SPDX-License-Identifier: Apache-2.0
"""
Threat-pattern detectors — heuristic regex surfacing for tool arguments.

Adapted from a log-analysis detector set (SQLi, command injection, SSRF, XXE,
XSS, path traversal), each tagged with a MITRE technique id. IMPORTANT framing:
these patterns were designed for *incoming log content*. Applied to a coding
agent's tool arguments they can false-positive on legitimate code (a developer
editing a `.sql` file, using `$(...)`, etc.). So detectors here are a SURFACING
layer, not a hard gate:

  critical -> ask     (pause for the human; do not silently block legit code)
  high     -> warn
  medium   -> warn
  low      -> allow (recorded only)

Today the strongest pattern below is rated `high`, so detectors only ever
surface/`warn`; the `critical -> ask` rung is reserved for future patterns and
is not reached by the current set (locked by tests/test_harness.py). Detectors
never block — hard blocks remain the job of the deterministic policy rules
(rm -rf, curl|bash, force-push). Every finding is written to the audit trail
(NIST MEASURE).

Deterministic, local, offline — pure regex.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# severity -> the strongest verdict a detector finding may suggest
SEVERITY_VERDICT = {"critical": "ask", "high": "warn", "medium": "warn", "low": "allow"}


@dataclass(frozen=True)
class Finding:
    name: str
    severity: str
    mitre: str
    description: str
    suggested_verdict: str


# Patterns most meaningful for a coding agent's tool calls come first.
_PATTERNS = [
    {
        "name": "command_injection",
        "pattern": re.compile(
            r"(;\s*(cat|ls|id|whoami|uname|wget|curl)\b)"
            r"|(\|\s*(cat|ls|id|whoami|uname)\b)"
            r"|(`[^`]*`)"
            r"|(\$\([^)]*\))",
            re.IGNORECASE,
        ),
        "severity": "medium",  # common in legit shell; surface, don't block
        "mitre": "T1059",
        "description": "Shell command-substitution / chaining pattern",
    },
    {
        "name": "ssrf_metadata",
        "pattern": re.compile(
            r"(169\.254\.169\.254)"          # cloud metadata endpoint
            r"|(http://0\.0\.0\.0[:/])"
            r"|(metadata\.google\.internal)",
            re.IGNORECASE,
        ),
        "severity": "high",
        "mitre": "T1190",
        "description": "Request to a cloud metadata / SSRF-sensitive endpoint",
    },
    {
        "name": "path_traversal",
        "pattern": re.compile(r"\.\./\.\./|%2e%2e%2f|%252e%252e", re.IGNORECASE),
        "severity": "medium",
        "mitre": "T1083",
        "description": "Path traversal sequence",
    },
    {
        "name": "sql_destructive",
        "pattern": re.compile(r";\s*DROP\s+TABLE\b|\bUNION\s+SELECT\b", re.IGNORECASE),
        "severity": "medium",
        "mitre": "T1190",
        "description": "Destructive / union SQL pattern",
    },
    {
        "name": "xxe",
        "pattern": re.compile(r"<!ENTITY|<!DOCTYPE[^>]*\[|SYSTEM\s+[\"']file://", re.IGNORECASE),
        "severity": "medium",
        "mitre": "T1190",
        "description": "XML External Entity (XXE) construct",
    },
]


def scan(text: str) -> list[Finding]:
    """Return all detector findings in `text` (a tool argument / command / content)."""
    if not text:
        return []
    findings: list[Finding] = []
    for p in _PATTERNS:
        if p["pattern"].search(text):
            sev = p["severity"]
            findings.append(
                Finding(
                    name=p["name"],
                    severity=sev,
                    mitre=p["mitre"],
                    description=p["description"],
                    suggested_verdict=SEVERITY_VERDICT.get(sev, "warn"),
                )
            )
    return findings


_RANK = {"allow": 0, "warn": 1, "ask": 2, "block": 3}


def worst_finding(findings: list[Finding]) -> Finding | None:
    if not findings:
        return None
    return max(findings, key=lambda f: _RANK.get(f.suggested_verdict, 0))

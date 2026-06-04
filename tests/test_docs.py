"""
Documentation UAT — the docs are tested against the real code, so they can't
drift. Every command, config snippet, MCP tool, standards row, and the worked
README example is verified here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "eldermind" / "policy.yaml"


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# README "Commands" table ↔ the actual CLI parser
# --------------------------------------------------------------------------
def _documented_commands() -> set[str]:
    readme = _read("README.md")
    block = readme.split("## Commands", 1)[1]
    return set(re.findall(r"`eldermind (\w[\w-]*)", block))


def _parser_subcommands() -> set[str]:
    from eldermind.cli import build_parser
    p = build_parser()
    # the first subparsers action holds the choices
    for a in p._subparsers._group_actions:  # type: ignore[attr-defined]
        if hasattr(a, "choices") and a.choices:
            return set(a.choices.keys())
    return set()


def test_every_documented_command_exists():
    documented = _documented_commands()
    real = _parser_subcommands()
    assert documented, "no commands parsed from README"
    missing = documented - real
    assert not missing, f"README documents commands that don't exist: {missing}"


def test_no_user_command_is_undocumented():
    # internal-only 'hook' is intentionally not in the user Commands table
    real = _parser_subcommands() - {"hook"}
    documented = _documented_commands()
    undocumented = real - documented
    assert not undocumented, f"CLI commands missing from README Commands table: {undocumented}"


# --------------------------------------------------------------------------
# The worked README example must be exactly reproducible (deterministic ids)
# --------------------------------------------------------------------------
def test_readme_block_example_is_accurate():
    from eldermind.decide import decide
    readme = _read("README.md")
    d = decide("bash", "git push --force origin main", policy=POLICY)
    # values quoted in the README banner/quick-start
    assert d.verdict == "block"
    assert d.asi == "ASI02"
    assert d.risk["score"] == 16
    assert d.risk["tier"] == "elevated_review"
    assert d.decision_id in readme, f"README shows a stale decision id; real is {d.decision_id}"
    assert "ASI02 Tool Misuse" in readme
    assert "16/25 (elevated_review)" in readme


def test_readme_quickstart_rm_rf_blocks():
    # install.py prints this as the Verify line; README echoes the contract
    from eldermind.decide import decide
    assert decide("bash", "rm -rf /", policy=POLICY).verdict == "block"


# --------------------------------------------------------------------------
# MCP tool list in README ↔ server source
# --------------------------------------------------------------------------
def test_documented_mcp_tools_exist():
    readme = _read("README.md")
    listed = set(re.findall(r"`(govern_check|council_review|scan|pin_check|audit_log|audit_summary)`", readme))
    server_src = _read("eldermind/server.py")
    for tool in listed:
        assert re.search(rf"def {tool}\b", server_src), f"README lists MCP tool '{tool}' not defined in server.py"
    assert {"govern_check", "council_review", "scan", "pin_check"} <= listed


# --------------------------------------------------------------------------
# Supported IDEs claimed in docs ↔ installer registry
# --------------------------------------------------------------------------
def test_install_supports_documented_ides():
    from eldermind.install import _INSTALLERS
    assert set(_INSTALLERS) == {"claude-code", "opencode", "kiro", "cursor"}
    ide_doc = _read("docs/IDE-SUPPORT.md")
    for ide in ("Claude Code", "OpenCode", "Kiro", "Cursor"):
        assert ide in ide_doc


def test_ide_support_mcp_snippet_matches_installer():
    from eldermind.install import _MCP_ENTRY
    assert _MCP_ENTRY == {"command": "eldermind", "args": ["serve"]}
    ide_doc = _read("docs/IDE-SUPPORT.md")
    assert '"command": "eldermind", "args": ["serve"]' in ide_doc


# --------------------------------------------------------------------------
# STANDARDS-MAP crosswalk ↔ policy.yaml (rule → ASI) and OWASP titles
# --------------------------------------------------------------------------
def _policy_rule_asi() -> dict[str, str]:
    import yaml
    pol = yaml.safe_load(POLICY.read_text())
    return {r["id"]: r.get("asi", "") for r in pol["rules"]}


def test_standards_map_rules_match_policy():
    rules = _policy_rule_asi()
    crosswalk = _read("docs/STANDARDS-MAP.md")
    # any rule id named in the crosswalk must carry its real ASI somewhere on that row
    for line in crosswalk.splitlines():
        for rid, asi in rules.items():
            if f"`{rid}`" in line and asi:
                assert asi in line, f"STANDARDS-MAP row for {rid} is missing/:wrong ASI {asi}: {line}"


def test_owasp_titles_consistent():
    from eldermind.decide import _ASI_NAMES
    sm = _read("docs/STANDARDS-MAP.md")
    # the official titles the code uses must appear verbatim in the standards doc
    for code, title in {
        "ASI02": "Tool Misuse",
        "ASI04": "Agentic Supply Chain",
        "ASI05": "Unexpected Code Execution",
    }.items():
        assert title in _ASI_NAMES[code]
        assert title in sm, f"STANDARDS-MAP missing OWASP title for {code}: {title}"


# --------------------------------------------------------------------------
# Dev-setup commands in TESTING.md / CONTRIBUTING ↔ pyproject extras
# --------------------------------------------------------------------------
def test_documented_extras_exist():
    pyproject = _read("pyproject.toml")
    for extra in ("mcp", "dev"):
        assert re.search(rf"^{extra} =", pyproject, re.M), f"docs reference [{extra}] extra not in pyproject"
    for doc in ("docs/TESTING.md", "CONTRIBUTING.md"):
        assert 'pip install -e ".[mcp,dev]"' in _read(doc)


# --------------------------------------------------------------------------
# Tier semantics described in README ↔ gate behaviour
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# QA guard — no internal / private architecture references leak into the repo.
# (Brand terms "Elder Mind" / "Cyber Elders" / cyberelders.com are intentional.)
# --------------------------------------------------------------------------
_FORBIDDEN = re.compile(
    r"192\.168\.|157\.90\.24|\bds9\b|\bds10\b|jarvis|hetzner|gitea\.cyberelders|:2222|:4444|:3333"
    r"|compliance-risk-agent|ops-executive|platform-agent|infrastructure-monitor"
    r"|methodology-v8|F11-RISK|sentineldecoy|\beldernats\b|cost portal|advocatus|cio-agent"
    r"|Sovereign Override|\bNATS\b|\bmTLS\b|Merkle|/Users/|kovnaidoo|cbb4d2eb|gho_[A-Za-z0-9]"
    r"|para_bucket|pre-existing-PARA|secret_scan_status",  # internal PARA knowledge-mgmt frontmatter
    re.IGNORECASE,
)
_SCAN_EXT = {".md", ".py", ".toml", ".yaml", ".yml", ".json", ".js", ".mdc", ".txt"}


def test_no_internal_private_references():
    self = Path(__file__).name
    offenders: list[str] = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or p.suffix not in _SCAN_EXT:
            continue
        parts = set(p.relative_to(ROOT).parts)
        if {".venv", ".git", "dist", "__pycache__", ".eldermind"} & parts or p.name == self:
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        for i, line in enumerate(text.splitlines(), 1):
            if _FORBIDDEN.search(line):
                offenders.append(f"{p.relative_to(ROOT)}:{i}: {line.strip()[:80]}")
    assert not offenders, "internal/private references leaked into the public repo:\n" + "\n".join(offenders)


def test_readme_tier_descriptions_match_behaviour():
    from eldermind.config import Config
    from eldermind.gate import evaluate
    readme = _read("README.md")
    assert "explorer" in readme and "operator" in readme
    # explorer relaxes ask→warn but not block; operator escalates ask→block
    assert evaluate("edit", "/repo/.env", policy=POLICY, config=Config(tier="explorer"))["verdict"] == "warn"
    assert evaluate("edit", "/repo/.env", policy=POLICY, config=Config(tier="operator"))["verdict"] == "block"
    assert evaluate("bash", "rm -rf /", policy=POLICY, config=Config(tier="explorer"))["verdict"] == "block"

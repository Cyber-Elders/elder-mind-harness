# SPDX-License-Identifier: Apache-2.0
"""
Tests for `eldermind install <tool>` — the install flow that wires the gate into
each harness. It is the first thing every user runs; a silent miswrite means the
gate never fires ("looks installed, isn't enforcing"). Covers file creation,
content, MCP registration, the written config, unknown-tool handling, merge
safety (never clobber existing settings), and idempotency (safe re-run).
"""

from __future__ import annotations

import json

from eldermind import install as installer
from eldermind.install import install


def _read_json(p):
    return json.loads(p.read_text())


# ---- claude-code -----------------------------------------------------------
def test_install_claude_code_writes_hook_and_mcp(tmp_path):
    rc = install("claude-code", target_dir=str(tmp_path))
    assert rc == 0
    # policy + config dropped
    assert (tmp_path / ".eldermind" / "policy.yaml").exists()
    cfg = (tmp_path / ".eldermind" / "config.toml").read_text()
    assert 'tier = "practitioner"' in cfg
    # PreToolUse hook merged into .claude/settings.json
    settings = _read_json(tmp_path / ".claude" / "settings.json")
    pre = settings["hooks"]["PreToolUse"]
    cmds = [h["command"] for e in pre for h in e.get("hooks", [])]
    assert "eldermind hook claude-code" in cmds
    assert pre[0]["matcher"] == installer._CLAUDE_MATCHER
    # advisory MCP server registered
    mcp = _read_json(tmp_path / ".mcp.json")
    assert mcp["mcpServers"]["eldermind"] == installer._MCP_ENTRY


def test_install_claude_code_idempotent(tmp_path):
    install("claude-code", target_dir=str(tmp_path))
    first = (tmp_path / ".claude" / "settings.json").read_text()
    rc = install("claude-code", target_dir=str(tmp_path))  # re-run
    assert rc == 0
    second = (tmp_path / ".claude" / "settings.json").read_text()
    assert first == second  # re-run does not rewrite
    # exactly ONE PreToolUse hook carrying our command (no duplicate)
    pre = _read_json(tmp_path / ".claude" / "settings.json")["hooks"]["PreToolUse"]
    mine = [h for e in pre for h in e.get("hooks", []) if h.get("command") == "eldermind hook claude-code"]
    assert len(mine) == 1


def test_install_claude_code_preserves_existing_settings(tmp_path):
    # a pre-existing unrelated hook + setting must survive the merge, not be clobbered
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(json.dumps({
        "theme": "dark",
        "hooks": {"PreToolUse": [{"matcher": "X", "hooks": [{"type": "command", "command": "other-tool"}]}]},
    }))
    install("claude-code", target_dir=str(tmp_path))
    data = _read_json(settings_path)
    assert data["theme"] == "dark"  # untouched
    cmds = [h["command"] for e in data["hooks"]["PreToolUse"] for h in e.get("hooks", [])]
    assert "other-tool" in cmds and "eldermind hook claude-code" in cmds  # merged


# ---- opencode --------------------------------------------------------------
def test_install_opencode(tmp_path):
    install("opencode", target_dir=str(tmp_path))
    plugin = tmp_path / ".opencode" / "plugins" / "eldermind.js"
    assert plugin.exists() and "tool.execute.before" in plugin.read_text()
    mcp = _read_json(tmp_path / "opencode.json")
    assert mcp["mcp"]["eldermind"] == installer._OPENCODE_MCP_ENTRY


# ---- kiro ------------------------------------------------------------------
def test_install_kiro(tmp_path):
    install("kiro", target_dir=str(tmp_path))
    agent = _read_json(tmp_path / ".kiro" / "agents" / "eldermind.json")
    assert agent["hooks"]["preToolUse"][0]["command"] == "eldermind hook kiro"
    assert (tmp_path / ".kiro" / "steering" / "eldermind.md").exists()
    mcp = _read_json(tmp_path / ".kiro" / "settings" / "mcp.json")
    assert mcp["mcpServers"]["eldermind"] == installer._MCP_ENTRY


# ---- cursor (advisory) -----------------------------------------------------
def test_install_cursor_advisory(tmp_path):
    install("cursor", target_dir=str(tmp_path))
    rule = tmp_path / ".cursor" / "rules" / "eldermind.mdc"
    assert rule.exists() and "advisory" in rule.read_text().lower()
    mcp = _read_json(tmp_path / ".cursor" / "mcp.json")
    assert mcp["mcpServers"]["eldermind"] == installer._MCP_ENTRY


# ---- misc ------------------------------------------------------------------
def test_install_unknown_tool_returns_1(tmp_path):
    assert install("emacs", target_dir=str(tmp_path)) == 1


def test_install_supplychain_flag_and_tier_in_config(tmp_path):
    install("claude-code", target_dir=str(tmp_path), supplychain=True, tier="operator")
    cfg = (tmp_path / ".eldermind" / "config.toml").read_text()
    assert "enabled = true" in cfg
    assert 'tier = "operator"' in cfg


def test_install_does_not_clobber_customized_policy(tmp_path):
    install("claude-code", target_dir=str(tmp_path))
    pol = tmp_path / ".eldermind" / "policy.yaml"
    custom = "version: '0.1'\ndefaults: {unmatched: allow, on_error: ask}\nrules: []\n"
    pol.write_text(custom)
    install("claude-code", target_dir=str(tmp_path))  # re-run must leave a user policy intact
    assert pol.read_text() == custom

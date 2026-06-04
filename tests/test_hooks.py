"""
Hard-block adapter contract tests — the IDE integration surface (harness.py).

The rest of the suite calls evaluate()/decide() directly; these tests go through
`run_hook(<tool>, <stdin>)` end to end, so they verify the load-bearing claim
("hard-block adapters") that nothing else covers: that a block verdict is
translated into each harness's NATIVE deny signal (Claude Code permissionDecision,
OpenCode/Kiro exit code 2), and that malformed/unknown input fails safe.

A regression here means the gate computes the right verdict and then mis-reports
it to the IDE — silently not enforcing while every other test stays green.
"""

from __future__ import annotations

import json

import pytest

from eldermind.harness import _target_from_input, run_hook


@pytest.fixture(autouse=True)
def _isolate_audit(monkeypatch, tmp_path):
    # Hooks write an audit entry; keep it out of the repo / cwd.
    monkeypatch.setenv("ELDERMIND_DIR", str(tmp_path / ".eldermind"))


# --------------------------------------------------------------------------
# Claude Code — PreToolUse: emits hookSpecificOutput.permissionDecision, exit 0.
# --------------------------------------------------------------------------
def test_claude_block_emits_deny(capsys):
    event = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "cwd": "/repo"}
    rc = run_hook("claude-code", json.dumps(event))
    out = json.loads(capsys.readouterr().out)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "permissionDecisionReason" in out["hookSpecificOutput"]
    assert rc == 0  # Claude reads the JSON decision; exit stays 0 by design


def test_claude_allow_emits_allow(capsys):
    event = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}, "cwd": "/repo"}
    rc = run_hook("claude-code", json.dumps(event))
    out = json.loads(capsys.readouterr().out)
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert rc == 0


def test_claude_secret_write_asks(capsys):
    event = {"tool_name": "Write", "tool_input": {"file_path": "/repo/.env"}, "cwd": "/repo"}
    run_hook("claude-code", json.dumps(event))
    out = json.loads(capsys.readouterr().out)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


# --------------------------------------------------------------------------
# OpenCode — tool.execute.before plugin: exit 2 on ask/block (the plugin throws).
# --------------------------------------------------------------------------
def test_opencode_block_exits_2(capsys):
    event = {"tool": "bash", "args": {"command": "rm -rf /"}}
    rc = run_hook("opencode", json.dumps(event))
    decision = json.loads(capsys.readouterr().out)
    assert decision["verdict"] == "block"
    assert rc == 2


def test_opencode_allow_exits_0(capsys):
    event = {"tool": "bash", "args": {"command": "git status"}}
    rc = run_hook("opencode", json.dumps(event))
    assert rc == 0


# --------------------------------------------------------------------------
# Kiro — preToolUse agent hook: exit 2 on ask/block + stderr reason (best-effort).
# --------------------------------------------------------------------------
def test_kiro_block_exits_2(capsys):
    event = {"tool_name": "execute_bash", "tool_input": {"command": "rm -rf /"}}
    rc = run_hook("kiro", json.dumps(event))
    captured = capsys.readouterr()
    decision = json.loads(captured.out)
    assert decision["verdict"] == "block"
    assert rc == 2
    assert "eldermind blocked" in captured.err


def test_kiro_allow_exits_0():
    event = {"tool_name": "fs_read", "tool_input": {"path": "/repo/src/main.py"}}
    rc = run_hook("kiro", json.dumps(event))
    assert rc == 0


# --------------------------------------------------------------------------
# Fail-safe behaviour
# --------------------------------------------------------------------------
def test_malformed_event_fails_safe():
    # Unparseable stdin must stop the call (exit 2), never silent-allow.
    assert run_hook("claude-code", "this is not json") == 2


def test_unknown_harness_errors():
    assert run_hook("nessie", "{}") == 1


# --------------------------------------------------------------------------
# Primary-argument extraction across harness payload shapes
# --------------------------------------------------------------------------
def test_block_reason_is_structured_and_actionable():
    """The block message a user actually sees must match the README/demo promise:
    consequence + OWASP/NIST mapping + decision id + audit path + the escape hatch.
    Guards against the message silently regressing to a terse one-liner."""
    from pathlib import Path

    from eldermind.decide import decide
    from eldermind.harness import _format_reason

    policy = Path(__file__).resolve().parent.parent / "eldermind" / "policy.yaml"
    d = decide("bash", "git push --force origin main", policy=policy).to_dict()
    r = _format_reason(d, "bash", "git push --force origin main")
    assert "⛔ Elder Mind blocked: bash(git push --force origin main)" in r
    assert "OWASP ASI02 Tool Misuse" in r
    assert "NIST RMF: MANAGE" in r
    assert "⚠ This tool use can damage your system or exfiltrate data." in r
    assert "logged to .eldermind/audit.jsonl" in r
    assert "to allow: add a rule to .eldermind/policy.yaml" in r  # the escape hatch must ship


@pytest.mark.parametrize("tool_input,expected", [
    ({"command": "rm -rf /"}, "rm -rf /"),
    ({"file_path": "/repo/.env"}, "/repo/.env"),
    ({"path": "/etc/hosts"}, "/etc/hosts"),
    ({"url": "http://169.254.169.254/"}, "http://169.254.169.254/"),
    ({"notebook_path": "/repo/x.ipynb"}, "/repo/x.ipynb"),
])
def test_target_extraction(tool_input, expected):
    assert _target_from_input("any", tool_input) == expected

"""
Per-harness translation for the hard-enforcement hook path.

`eldermind hook <tool>` reads the harness's native pre-tool event on
stdin, translates it into the common request shape, runs decide(), writes the
audit entry, then emits the harness's native allow/deny/ask response and exit
code. This keeps each on-disk adapter trivial — it only needs to point the
harness's pre-tool hook at `eldermind hook <tool>`.

Common request shape: {"action": <tool>, "target": <primary arg>, "context": {...}}
Verdict -> exit code: allow/warn -> 0 (proceed), ask/block -> 2 (stop).
"""

from __future__ import annotations

import json
import sys

from .audit import record
from .gate import evaluate_json

# Harness-native tool names -> our normalized action vocabulary.
_TOOL_ALIASES = {
    "bash": "bash",
    "shell": "bash",
    "edit": "edit",
    "multiedit": "edit",
    "write": "write",
    "read": "read",
    "cat": "read",
    "str_replace_editor": "edit",
    "str_replace_based_edit_tool": "edit",
    # Kiro tool names
    "execute_bash": "bash",
    "fs_write": "write",
    "fs_read": "read",
    # Windows shells — pass through so windows-* policy rules match
    "powershell": "powershell",
    "pwsh": "powershell",
    "cmd": "cmd",
}


def _normalize_tool(name: str) -> str:
    return _TOOL_ALIASES.get((name or "").lower(), (name or "").lower())


def _target_from_input(tool: str, tool_input: dict) -> str:
    """Pull the primary argument out of a harness tool_input dict."""
    if not isinstance(tool_input, dict):
        return str(tool_input)
    for key in ("command", "file_path", "path", "filePath", "target", "cmd", "content"):
        if key in tool_input and tool_input[key]:
            return str(tool_input[key])
    # Fall back to the whole thing so a rule can still inspect it.
    return json.dumps(tool_input, ensure_ascii=False)


# --------------------------------------------------------------------------
# Claude Code  (PreToolUse)
# stdin: {"tool_name": "Bash", "tool_input": {"command": "..."}, "cwd": "..."}
# We emit hookSpecificOutput with permissionDecision and exit 0; Claude Code
# honours the JSON. (Exit 2 also blocks, as a belt-and-suspenders fallback.)
# --------------------------------------------------------------------------
def _hook_claude_code(event: dict) -> int:
    action = _normalize_tool(event.get("tool_name", ""))
    target = _target_from_input(action, event.get("tool_input", {}))
    context = {"agent": "claude-code", "cwd": event.get("cwd", "")}
    decision = evaluate_json({"action": action, "target": target, "context": context})
    _safe_record(decision, context)

    verdict = decision["verdict"]
    reason = _format_reason(decision)
    if verdict == "block":
        perm = "deny"
    elif verdict == "ask":
        perm = "ask"
    else:  # allow / warn -> proceed
        if verdict == "warn":
            sys.stderr.write(f"eldermind: {reason}\n")
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }}))
        return 0

    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": perm,
        "permissionDecisionReason": reason,
    }}))
    return 0  # JSON carries the decision; exit 0 so Claude Code reads it


# --------------------------------------------------------------------------
# OpenCode  (tool.execute.before, invoked by the JS plugin shim)
# stdin: {"tool": "bash", "args": {"command": "..."}}  (shape we define)
# We print the decision JSON; the JS plugin throws on block/ask.
# --------------------------------------------------------------------------
def _hook_opencode(event: dict) -> int:
    action = _normalize_tool(event.get("tool", event.get("action", "")))
    raw_args = event.get("args", event.get("tool_input", event.get("target", {})))
    target = raw_args if isinstance(raw_args, str) else _target_from_input(action, raw_args)
    context = {"agent": "opencode"}
    decision = evaluate_json({"action": action, "target": target, "context": context})
    _safe_record(decision, context)
    print(json.dumps(decision))
    return 0 if decision["verdict"] in ("allow", "warn") else 2


# --------------------------------------------------------------------------
# Kiro  (preToolUse agent hook)
# Kiro's exact payload schema is not fully published; we read defensively and
# rely on exit code (0 allow, 2 block) + a stderr reason, the most universally
# honoured mechanism. Best-effort pending live verification.
# --------------------------------------------------------------------------
def _hook_kiro(event: dict) -> int:
    # Kiro's confirmed stdin fields are snake_case (tool_name / tool_input),
    # matching Claude Code. Fall back to other casings defensively.
    action = _normalize_tool(
        event.get("tool_name", event.get("toolName", event.get("tool", "")))
    )
    raw = event.get("tool_input", event.get("toolInput", event.get("input", event.get("args", {}))))
    target = raw if isinstance(raw, str) else _target_from_input(action, raw)
    context = {"agent": "kiro"}
    decision = evaluate_json({"action": action, "target": target, "context": context})
    _safe_record(decision, context)

    reason = _format_reason(decision)
    print(json.dumps(decision))
    if decision["verdict"] in ("ask", "block"):
        sys.stderr.write(f"eldermind blocked: {reason}\n")
        return 2
    if decision["verdict"] == "warn":
        sys.stderr.write(f"eldermind warning: {reason}\n")
    return 0


_HOOKS = {
    "claude-code": _hook_claude_code,
    "opencode": _hook_opencode,
    "kiro": _hook_kiro,
}


def _format_reason(decision: dict) -> str:
    risk = decision.get("risk") or {}
    score = risk.get("score")
    tier = risk.get("tier")
    # Lead with the plain-language consequence so the human sees what's at stake.
    preview = decision.get("preview")
    base = f"⚠ {preview}  {decision.get('reason', '')}" if preview else decision.get("reason", "")
    if score is not None:
        base += f" · risk {score}/25 ({tier}) · {decision.get('decision_id')}"
    return base


def _safe_record(decision: dict, context: dict) -> None:
    try:
        record(decision, outcome="gated", context=context)
    except OSError:
        pass


def run_hook(tool: str, stdin_text: str) -> int:
    """Entry point for `eldermind hook <tool>`."""
    handler = _HOOKS.get(tool)
    if handler is None:
        sys.stderr.write(f"unknown harness: {tool}\n")
        return 1
    text = (stdin_text or "").strip()
    try:
        event = json.loads(text) if text else {}
    except json.JSONDecodeError:
        # Fail-safe: unparseable event -> ask (exit 2), never silent allow.
        sys.stderr.write("eldermind: could not parse harness event; failing safe\n")
        return 2
    return handler(event)

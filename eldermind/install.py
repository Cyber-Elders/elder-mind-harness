# SPDX-License-Identifier: Apache-2.0
"""
`eldermind install <tool>` — wire the gate into a harness, idempotently.

For each tool it:
  1. drops the default policy into <project>/.eldermind/policy.yaml (if absent),
  2. registers the advisory MCP server, and
  3. installs the hard-enforcement pre-tool hook in the tool's native config.

It never clobbers existing settings — it merges, and is safe to re-run. Every
change is printed. The MCP server is registered identically across all three
tools (command: `eldermind serve`).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

# Claude Code tool names (PreToolUse matcher). Includes NotebookEdit/WebFetch/
# Task and any MCP tool (mcp__*) so a tool outside the core five — e.g. a
# malicious MCP server's tool running shell-equivalent actions — still hits the
# gate (the policy's unmatched:allow default keeps benign calls cheap).
_CLAUDE_MATCHER = "Bash|Edit|Write|Read|MultiEdit|NotebookEdit|WebFetch|Task|mcp__.*"
# Kiro tool names (preToolUse matcher).
_KIRO_MATCHER = "execute_bash|fs_write|fs_read"

# Standard MCP server entry (Claude Code .mcp.json, Kiro .kiro/settings/mcp.json).
_MCP_ENTRY = {"command": "eldermind", "args": ["serve"]}
# OpenCode uses a different shape: type + command-as-array + enabled.
_OPENCODE_MCP_ENTRY = {"type": "local", "command": ["eldermind", "serve"], "enabled": True}

_OPENCODE_PLUGIN_JS = """\
// eldermind — OpenCode pre-tool-use enforcement shim.
// Installed by `eldermind install opencode`.
// Spawns the deterministic gate CLI and blocks the tool call on ask/block.
import { spawnSync } from "node:child_process";

export const hooks = {
  "tool.execute.before": async (input) => {
    const payload = JSON.stringify({
      tool: input?.tool ?? input?.name ?? "",
      args: input?.args ?? input?.input ?? {},
    });
    const res = spawnSync("eldermind", ["hook", "opencode"], {
      input: payload,
      encoding: "utf-8",
    });
    let decision = {};
    try { decision = JSON.parse((res.stdout || "").trim() || "{}"); } catch (_) {}
    if (decision.verdict === "block" || decision.verdict === "ask") {
      throw new Error(
        `eldermind ${decision.verdict}: ${decision.reason || "policy violation"} ` +
        `(risk ${decision.risk?.score}/25, ${decision.decision_id})`
      );
    }
    return input;
  },
};
"""

_KIRO_STEERING_MD = """\
---
inclusion: always
---
# eldermind governance

A deterministic pre-tool-use gate is active on this project. Before running
shell commands or editing sensitive files, expect the gate to evaluate the
action against `.eldermind/policy.yaml` and block or ask on high-risk calls.
If a call is blocked, explain the OWASP-mapped reason to the user rather than
trying to bypass the gate.
"""

_AGENTS_SNIPPET = """\

## eldermind (active)
A deterministic pre-tool-use governance gate evaluates tool calls against
`.eldermind/policy.yaml` (OWASP Agentic Top 10 aware, NIST AI RMF aligned).
High-risk calls (destructive deletes, remote code execution, force-push to
protected branches, secrets access) are blocked or require confirmation. You
may also call the `govern_check` MCP tool proactively before risky actions.
Do not attempt to bypass the gate; surface its reason to the user.
"""


def _changes() -> list[str]:
    return []


def _project_dir(target_dir: str | None) -> Path:
    return Path(target_dir).resolve() if target_dir else Path.cwd()


def _ensure_policy(root: Path, changes: list[str]) -> None:
    dest = root / ".eldermind" / "policy.yaml"
    if dest.exists():
        changes.append(f"= {dest} (already present, left unchanged)")
        return
    bundled = Path(__file__).resolve().parent / "policy.yaml"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if bundled.exists():
        shutil.copyfile(bundled, dest)
    else:  # pragma: no cover - bundled policy should always exist
        dest.write_text("version: '0.1'\ndefaults: {unmatched: allow, on_error: ask}\nrules: []\n")
    changes.append(f"+ {dest} (default policy)")


def _load_json(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text() or "{}")
        except json.JSONDecodeError:
            return {}
    return {}


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _register_mcp(path: Path, key: str, entry: dict, changes: list[str]) -> None:
    data = _load_json(path)
    servers = data.setdefault(key, {})
    if servers.get("eldermind") == entry:
        changes.append(f"= {path} (MCP server already registered)")
        return
    servers["eldermind"] = entry
    _write_json(path, data)
    changes.append(f"~ {path} (registered MCP server 'eldermind')")


def _install_claude_code(root: Path, changes: list[str]) -> None:
    # Hard-enforcement hook
    settings = root / ".claude" / "settings.json"
    data = _load_json(settings)
    hooks = data.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    cmd = "eldermind hook claude-code"
    already = any(
        any(h.get("command") == cmd for h in entry.get("hooks", []))
        for entry in pre
        if isinstance(entry, dict)
    )
    if already:
        changes.append(f"= {settings} (PreToolUse hook already present)")
    else:
        pre.append({"matcher": _CLAUDE_MATCHER, "hooks": [{"type": "command", "command": cmd}]})
        _write_json(settings, data)
        changes.append(f"~ {settings} (added PreToolUse hook)")
    # Advisory MCP server (.mcp.json, key "mcpServers")
    _register_mcp(root / ".mcp.json", "mcpServers", _MCP_ENTRY, changes)


def _install_opencode(root: Path, changes: list[str]) -> None:
    # OpenCode plugins live in .opencode/plugins/ (plural).
    plugin = root / ".opencode" / "plugins" / "eldermind.js"
    if plugin.exists() and plugin.read_text() == _OPENCODE_PLUGIN_JS:
        changes.append(f"= {plugin} (plugin already present)")
    else:
        plugin.parent.mkdir(parents=True, exist_ok=True)
        plugin.write_text(_OPENCODE_PLUGIN_JS)
        changes.append(f"+ {plugin} (tool.execute.before plugin)")
    # OpenCode MCP config: opencode.json, key "mcp", entry shape {type, command[], enabled}
    _register_mcp(root / "opencode.json", "mcp", _OPENCODE_MCP_ENTRY, changes)


def _install_kiro(root: Path, changes: list[str]) -> None:
    # Kiro pre-tool hooks attach to an agent config under hooks.preToolUse.
    agent = root / ".kiro" / "agents" / "eldermind.json"
    agent_cfg = {
        "name": "eldermind",
        "description": "Deterministic pre-tool-use governance gate (OWASP/NIST aligned).",
        "hooks": {
            "preToolUse": [
                {"matcher": _KIRO_MATCHER, "command": "eldermind hook kiro"}
            ]
        },
    }
    if agent.exists() and _load_json(agent) == agent_cfg:
        changes.append(f"= {agent} (agent hook already present)")
    else:
        _write_json(agent, agent_cfg)
        changes.append(f"~ {agent} (preToolUse hook in agent config)")
    steering = root / ".kiro" / "steering" / "eldermind.md"
    if not steering.exists():
        steering.parent.mkdir(parents=True, exist_ok=True)
        steering.write_text(_KIRO_STEERING_MD)
        changes.append(f"+ {steering} (steering file)")
    else:
        changes.append(f"= {steering} (steering already present)")
    _register_mcp(root / ".kiro" / "settings" / "mcp.json", "mcpServers", _MCP_ENTRY, changes)


_CURSOR_RULES_MD = """\
---
description: Elder Mind governance — check risky actions before running them.
alwaysApply: true
---
# Elder Mind governance (advisory)

Cursor has no blocking pre-tool hook, so governance here is advisory. Before you
run a shell command, edit/read a sensitive file (.env, keys, .npmrc, .claude/,
.vscode/, CI config), or install a dependency, call the `govern_check` MCP tool
(action, target) and honour its verdict:
- block / ask → stop and surface the reason to the user (do not proceed silently)
- warn → proceed but tell the user why it was flagged
Record sensitive actions with `audit_log`. Do not try to bypass the gate.
"""


def _install_cursor(root: Path, changes: list[str]) -> None:
    # Cursor: no blocking pre-tool hook → advisory MCP + an always-on rule.
    rules = root / ".cursor" / "rules" / "eldermind.mdc"
    if rules.exists() and rules.read_text() == _CURSOR_RULES_MD:
        changes.append(f"= {rules} (rule already present)")
    else:
        rules.parent.mkdir(parents=True, exist_ok=True)
        rules.write_text(_CURSOR_RULES_MD)
        changes.append(f"+ {rules} (advisory rule)")
    _register_mcp(root / ".cursor" / "mcp.json", "mcpServers", _MCP_ENTRY, changes)
    changes.append("! Cursor is ADVISORY only (no hard pre-tool block) — see docs/IDE-SUPPORT.md")


_INSTALLERS = {
    "claude-code": _install_claude_code,
    "opencode": _install_opencode,
    "kiro": _install_kiro,
    "cursor": _install_cursor,
}


def _write_config(root: Path, supplychain: bool, council_models: list[str], tier: str, changes: list[str]) -> None:
    cfg = root / ".eldermind" / "config.toml"
    models = ", ".join(f'"{m}"' for m in council_models)
    body = (
        "# Elder Mind Governance Harness — project config\n"
        f"[governance]\ntier = \"{tier}\"\n\n"
        f"[supplychain]\n# dynamic OSV check on package installs (may touch the network)\nenabled = {str(supplychain).lower()}\n\n"
        f"[council]\n# BYO-LLM: empty = use the host agent's own model; add model names if you route\nmodels = [{models}]\n"
    )
    cfg.parent.mkdir(parents=True, exist_ok=True)
    if cfg.exists() and cfg.read_text() == body:
        changes.append(f"= {cfg} (config unchanged)")
    else:
        cfg.write_text(body)
        changes.append(f"~ {cfg} (governance/supplychain/council config)")


def install(
    tool: str,
    target_dir: str | None = None,
    supplychain: bool = False,
    council_models: list[str] | None = None,
    tier: str = "practitioner",
) -> int:
    installer = _INSTALLERS.get(tool)
    if installer is None:
        print(f"unknown tool: {tool}")
        return 1
    root = _project_dir(target_dir)
    changes: list[str] = []
    _ensure_policy(root, changes)
    _write_config(root, supplychain, council_models or [], tier, changes)
    installer(root, changes)

    print(f"Elder Mind installed for {tool} in {root}")
    for line in changes:
        print(f"  {line}")
    print("\nLegend: + created · ~ modified · = unchanged")
    print(f"Supply-chain protection: {'ON' if supplychain else 'off'} · governance tier: {tier}")
    print("Verify:  echo '{\"action\":\"bash\",\"target\":\"rm -rf /\"}' | eldermind check")
    return 0


def guided_init(tool: str | None = None, target_dir: str | None = None) -> int:
    """Interactive wizard. Also usable AI-guided: the host agent can read
    skills/eldermind-init and call `eldermind install <tool> [--supplychain]`
    on the user's behalf with the answers it gathers."""
    print("Elder Mind Governance Harness — guided setup\n")

    def ask(prompt: str, default: str) -> str:
        try:
            ans = input(f"{prompt} [{default}]: ").strip()
        except EOFError:
            ans = ""
        return ans or default

    if tool is None:
        tool = ask("Which coding agent? (claude-code / opencode / kiro = hard-block · cursor = advisory)", "claude-code")
    if tool not in _INSTALLERS:
        print(f"unknown tool: {tool}")
        return 1

    tier = ask("Governance tier (explorer / practitioner / governed / operator)", "practitioner")
    sc_ans = ask("Enable supply-chain protection? (dynamic OSV check on installs; may use the network) (y/N)", "N")
    supplychain = sc_ans.lower().startswith("y")
    models_ans = ask("Council models for high-risk review — comma-separated, or blank to use your agent's own model", "")
    council_models = [m.strip() for m in models_ans.split(",") if m.strip()]

    return install(tool, target_dir=target_dir, supplychain=supplychain, council_models=council_models, tier=tier)

# Harness adapters

These are reference copies of what `eldermind install <tool>` writes into a
project. You normally don't edit them by hand — run the installer. They're here
so you can see exactly what gets wired in before you trust it.

All three hard-enforcement paths funnel into the same deterministic core via
`eldermind hook <tool>`, which reads the harness's native pre-tool event on
stdin and emits the harness's native allow/deny/ask response. One core, three
~20-line adapters.

| Tool | Mechanism | Files written |
|---|---|---|
| Claude Code | `PreToolUse` hook (command) | `.claude/settings.json` + `.mcp.json` (key `mcpServers`) |
| OpenCode | `tool.execute.before` plugin | `.opencode/plugins/eldermind.js` + `opencode.json` (key `mcp`, entry `{type, command[], enabled}`) |
| Kiro | `preToolUse` hook in agent config | `.kiro/agents/eldermind.json` + `.kiro/steering/eldermind.md` + `.kiro/settings/mcp.json` (key `mcpServers`) |

Config shapes verified against current docs (Claude Code hooks reference;
OpenCode plugins + MCP docs; Kiro CLI hooks + steering + MCP docs).

- **Claude Code** blocks via `hookSpecificOutput.permissionDecision` (`allow`/`deny`/`ask`); exit 2 also blocks.
- **OpenCode** blocks when the plugin `throw`s on `verdict` of `block`/`ask`.
- **Kiro** has no structured-denial JSON — it blocks on **exit code 2 + stderr** only. The matcher uses Kiro's tool names (`execute_bash|fs_write|fs_read`).

> **Note:** the Kiro adapter remains best-effort pending verification against a
> live Kiro install. The translator (`harness.py`) reads `tool_name`/`tool_input`
> (confirmed) with defensive fallbacks and relies on exit 2 to block.

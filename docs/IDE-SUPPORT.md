# IDE & OS support

Elder Mind meets the developer in their own coding agent, on their own OS. The
core gate is pure Python (Windows / macOS / Linux); what differs per IDE is
**whether the IDE can hard-block a tool call** (a pre-tool hook) or can only be
**advised** (MCP tool the agent is told to call).

## Support matrix

| IDE / agent | OS | Enforcement | How it installs |
|---|---|---|---|
| **Claude Code** | Win · macOS · Linux | **Hard block** (`PreToolUse`) | `eldermind init claude-code` → `.claude/settings.json` hook + `.mcp.json` |
| **OpenCode** | Win · macOS · Linux | **Hard block** (`tool.execute.before` plugin) | `eldermind init opencode` → `.opencode/plugins/` + `opencode.json` |
| **Kiro** | Win · macOS · Linux | **Hard block*** (`preToolUse` agent hook) | `eldermind init kiro` → `.kiro/agents/` hook + steering + MCP |
| **Cursor** | Win · macOS · Linux | **Advisory** (no blocking hook) | `eldermind init cursor` → `.cursor/rules/eldermind.mdc` + `.cursor/mcp.json` |
| **Windsurf / VS Code (Copilot) / Claude Desktop / any MCP client** | Win · macOS · Linux | **Advisory** | Register the MCP server (`eldermind serve`) and add a rule telling the agent to call `govern_check` before risky actions |

- **Hard block** = the IDE routes every tool call through Elder Mind's hook, which can deny/ask before the action runs. This is the strong enforcement path.
- **Advisory** = the IDE can't intercept tool calls, so the agent is *instructed* (via a rules/steering file) to call the `govern_check` MCP tool and honour the verdict. Weaker — relies on the agent following instructions — but still useful (and everything is audited).
- **\* Kiro is best-effort.** The Claude Code and OpenCode adapters are verified against their live pre-tool hooks; the **Kiro** adapter is implemented to Kiro's documented `preToolUse` agent-hook contract but is **pending verification against a live Kiro install**. It reads the payload defensively and falls back to the universally-honoured exit-code-2 + stderr mechanism, so it fails safe — but treat it as experimental until confirmed. See [`adapters/README.md`](../adapters/README.md).

## Cross-platform behaviour

- **Paths** are normalised before matching: a Windows path like `C:\Users\me\.aws\credentials` matches the same `**/.aws/credentials` rule as the POSIX form. Drive letters are stripped; backslashes treated as `/`.
- **Commands** are matched for both Unix and Windows shells: `rm -rf /` *and* PowerShell `Remove-Item -Recurse -Force`, `rd /s /q`, `del /s`, `format`; `curl … | bash` *and* `iwr … | iex`, `powershell -enc`.
- The `eldermind` CLI is the universal hook target on every OS (installed on PATH via `pipx install eldermind`). The OpenCode plugin and the hooks all shell out to it.

## Adding another MCP-capable IDE (advisory)

1. `eldermind serve` is the MCP server (stdio). Register it in your IDE's MCP config (`{"mcpServers": {"eldermind": {"command": "eldermind", "args": ["serve"]}}}`).
2. Add a short rule/steering note: *"Before running shell commands, editing sensitive files, or installing packages, call the `govern_check` tool and honour its verdict."*
3. For hard blocking, the IDE must expose a pre-tool-use hook — open an issue if yours does and isn't listed.

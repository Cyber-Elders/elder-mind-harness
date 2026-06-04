// eldermind — OpenCode pre-tool-use enforcement shim.
// Reference copy of what `eldermind install opencode` writes to
// .opencode/plugins/eldermind.js. Spawns the deterministic gate CLI and
// blocks the tool call on ask/block by throwing.
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

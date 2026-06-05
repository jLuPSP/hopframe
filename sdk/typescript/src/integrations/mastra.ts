// Adapter for Mastra (@mastra/core). Mastra agents declare tools as
// objects with an execute function; same wrapping pattern as the AI
// SDK adapter.
//
// We do NOT import @mastra/core directly to avoid a hard peer dep.

import type { Hopframe } from "../client.js";

export interface MastraTool {
  id?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  execute?: (ctx: { context: unknown }) => Promise<unknown> | unknown;
}

export interface WrapMastraToolOptions {
  hopframe: Hopframe;
  agentRunID?: string;
}

export function wrapMastraTool<T extends MastraTool>(tool: T, opts: WrapMastraToolOptions): T {
  if (!tool.execute) return tool;
  const original = tool.execute.bind(tool);
  return {
    ...tool,
    execute: async (ctx: { context: unknown }) => {
      const start = Date.now();
      const name = tool.id ?? "mastra-tool";
      opts.hopframe.emit({
        protocol: "mcp",
        direction: "inbound",
        agent_run_id: opts.agentRunID,
        message: { method: "tools/call", params: { name, arguments: ctx.context as Record<string, unknown> } },
      });
      try {
        const result = await original(ctx);
        opts.hopframe.emit({
          protocol: "mcp",
          direction: "outbound",
          agent_run_id: opts.agentRunID,
          message: {
            method: "tools/call",
            result: typeof result === "object" && result !== null ? (result as Record<string, unknown>) : { value: result as unknown },
          },
          latency_micros: (Date.now() - start) * 1000,
        });
        return result;
      } catch (err) {
        opts.hopframe.emit({
          protocol: "mcp",
          direction: "outbound",
          agent_run_id: opts.agentRunID,
          action: "warn",
          severity: "high",
          findings: [
            {
              rule_id: "mastra.tool_error",
              category: "transport",
              severity: "high",
              description: err instanceof Error ? err.message : String(err),
            },
          ],
          message: { method: "tools/call", params: { name } },
          latency_micros: (Date.now() - start) * 1000,
        });
        throw err;
      }
    },
  } as T;
}

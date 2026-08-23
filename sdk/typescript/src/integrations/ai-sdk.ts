// Adapter for Vercel AI SDK (`ai` package). Wraps generateText /
// streamText / experimental_generate calls to emit events for tool
// calls and tool results crossing the LLM boundary.
//
// The AI SDK's "tools" config is the most useful hook point: each tool
// invocation goes through the SDK before reaching the user's tool
// function, so wrapping at that layer captures the protocol shape
// Hopframe cares about.

import type { Hopframe } from "../client.js";

export interface WrapAISDKToolOptions {
  hopframe: Hopframe;
  agentRunID?: string;
  // Optional name override; defaults to the tool's declared name.
  toolName?: string;
}

// The AI SDK's tool() shape (we don't import the real type to avoid a
// hard peer dep). We only need execute and parameters.
export interface AISDKTool {
  description?: string;
  parameters?: unknown;
  execute?: (args: unknown, opts?: unknown) => Promise<unknown> | unknown;
}

// wrapAISDKTool wraps a single AI SDK tool. The wrapped tool emits an
// inbound event when invoked and an outbound event when the underlying
// execute resolves. Errors emit a high-severity finding.
export function wrapAISDKTool<T extends AISDKTool>(tool: T, opts: WrapAISDKToolOptions): T {
  if (!tool.execute) return tool;
  const original = tool.execute.bind(tool);
  const wrapped: T = {
    ...tool,
    execute: async (args: unknown, executeOpts?: unknown) => {
      const start = Date.now();
      const name = opts.toolName ?? "ai-sdk-tool";
      opts.hopframe.emit({
        protocol: "mcp",
        direction: "inbound",
        agent_run_id: opts.agentRunID,
        message: { method: "tools/call", params: { name, arguments: args as Record<string, unknown> } },
      });
      try {
        const result = await original(args, executeOpts);
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
              rule_id: "ai_sdk.tool_error",
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
  };
  return wrapped;
}

// wrapAISDKTools is the convenience for a tools record map.
export function wrapAISDKTools<T extends Record<string, AISDKTool>>(
  tools: T,
  opts: Omit<WrapAISDKToolOptions, "toolName">,
): T {
  const out: Record<string, AISDKTool> = {};
  for (const [name, tool] of Object.entries(tools)) {
    out[name] = wrapAISDKTool(tool, { ...opts, toolName: name });
  }
  return out as T;
}

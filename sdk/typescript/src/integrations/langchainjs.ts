// Adapter for LangChainJS. The LangChain callback shape is the
// standard hook for observing tool calls; this adapter exposes a
// callback handler the user attaches to their AgentExecutor or
// RunnableConfig.
//
// We do NOT import langchain directly to avoid a hard peer dep at
// compile. The callback handler shape below matches what LangChain
// expects at runtime; LangChain duck-types the methods.

import type { Hopframe } from "../client.js";
import { newRunID } from "../types.js";

export interface HopframeLangChainCallbackOptions {
  hopframe: Hopframe;
  // Optional run id; one is generated per handler instance if absent.
  runID?: string;
  // Optional sensor id override (defaults to client's).
  sensorID?: string;
}

// HopframeLangChainCallback is shaped like a BaseCallbackHandler from
// langchain core. LangChain duck-types these methods; the user does:
//
//   const cb = new HopframeLangChainCallback({ hopframe });
//   await agent.invoke({ ... }, { callbacks: [cb] });
export class HopframeLangChainCallback {
  readonly name = "HopframeLangChainCallback";
  private hf: Hopframe;
  private runID: string;

  constructor(opts: HopframeLangChainCallbackOptions) {
    this.hf = opts.hopframe;
    this.runID = opts.runID ?? newRunID();
  }

  handleToolStart(
    tool: { name?: string },
    input: string,
  ): Promise<void> | void {
    this.hf.emit({
      protocol: "mcp",
      direction: "inbound",
      agent_run_id: this.runID,
      message: {
        method: "tools/call",
        params: { name: tool?.name ?? "unknown", arguments: { input } },
      },
    });
  }

  handleToolEnd(output: string, _runId?: string): Promise<void> | void {
    this.hf.emit({
      protocol: "mcp",
      direction: "outbound",
      agent_run_id: this.runID,
      message: {
        method: "tools/call",
        result: { content: output },
      },
    });
  }

  handleToolError(err: Error | string): Promise<void> | void {
    this.hf.emit({
      protocol: "mcp",
      direction: "outbound",
      agent_run_id: this.runID,
      action: "warn",
      severity: "high",
      findings: [
        {
          rule_id: "langchainjs.tool_error",
          category: "transport",
          severity: "high",
          description: err instanceof Error ? err.message : String(err),
        },
      ],
      message: { method: "tools/call" },
    });
  }
}

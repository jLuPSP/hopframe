// MCP adapter. Wraps a client or server from
// @modelcontextprotocol/sdk so JSON-RPC envelopes crossing the wire
// emit Hopframe events. Useful when the agent framework is custom-Node
// and the inline Go sensor is not in the path.
//
// The adapter is a thin shim around the standard MCP transport layer.
// It does not run the four-layer detection pipeline; that lives in the
// Go sensor. Events emitted from this adapter land on the same control
// plane timeline and are matched against policies the operator
// authored, but the disposition is advisory: this code path does not
// itself block traffic.

import type { Hopframe } from "../client.js";
import type { Action, HopframeEvent, Protocol, Severity } from "../types.js";

// We intentionally do not import @modelcontextprotocol/sdk types
// directly; they would force a peer dep at compile. The shapes below
// are the minimum we observe at runtime.
type JsonRpcEnvelope = {
  jsonrpc?: "2.0";
  id?: string | number;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: Record<string, unknown>;
};

export interface WrapMCPClientOptions {
  hopframe: Hopframe;
  agentRunID?: string;
  counterparty?: string; // server identity
  source?: string;
  destination?: string;
}

export interface MCPSendable {
  send: (msg: JsonRpcEnvelope) => Promise<unknown>;
}

// wrapMCPClient returns a thin proxy around an MCP client transport.
// Every send() is observed: a request event is emitted before the call
// and a response event after. Errors emit a finding-bearing event with
// severity=high.
export function wrapMCPClient<T extends MCPSendable>(transport: T, opts: WrapMCPClientOptions): T {
  const { hopframe, agentRunID, counterparty, source, destination } = opts;
  return new Proxy(transport, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (prop !== "send" || typeof value !== "function") return value;
      return async function (this: unknown, msg: JsonRpcEnvelope) {
        const start = Date.now();
        emit(hopframe, msg, "inbound", "allow", "info", { agentRunID, counterparty, source, destination });
        try {
          const res = (await (value as MCPSendable["send"]).call(target, msg)) as JsonRpcEnvelope;
          if (res && typeof res === "object") {
            emit(hopframe, res, "outbound", "allow", "info", {
              agentRunID, counterparty, source, destination,
              latencyMicros: (Date.now() - start) * 1000,
            });
          }
          return res;
        } catch (err) {
          emit(hopframe, msg, "outbound", "warn", "high", {
            agentRunID, counterparty, source, destination,
            findings: [
              {
                rule_id: "mcp.adapter.transport_error",
                category: "transport",
                severity: "high",
                description: errorMessage(err),
              },
            ],
            latencyMicros: (Date.now() - start) * 1000,
          });
          throw err;
        }
      };
    },
  });
}

interface EmitContext {
  agentRunID?: string;
  counterparty?: string;
  source?: string;
  destination?: string;
  latencyMicros?: number;
  findings?: HopframeEvent["findings"];
}

function emit(
  hf: Hopframe,
  env: JsonRpcEnvelope,
  direction: HopframeEvent["direction"],
  action: Action,
  severity: Severity,
  ctx: EmitContext,
): void {
  const protocol: Protocol = "mcp";
  const ev = hf.emit({
    protocol,
    direction,
    agent_run_id: ctx.agentRunID,
    counterparty: ctx.counterparty,
    source: ctx.source,
    destination: ctx.destination,
    action,
    severity,
    findings: ctx.findings,
    message: {
      id: env.id != null ? String(env.id) : undefined,
      method: env.method,
      params: env.params,
      result: env.result,
      error: env.error,
      raw: safeStringify(env),
    },
  });
  if (ctx.latencyMicros) ev.latency_micros = ctx.latencyMicros;
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v);
  } catch {
    return "";
  }
}

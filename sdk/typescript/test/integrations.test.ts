// Adapter smoke tests for langchainjs / mastra / mcp. The base
// Hopframe client is already covered in client.test.ts; these tests
// focus on the per-framework adapters and the shape of the events
// they emit.
//
// We don't import any of the actual frameworks (LangChain, Mastra,
// @modelcontextprotocol/sdk) since the adapters are deliberately
// peer-dep-less; runtime duck-typing is enough.

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { Hopframe } from "../src/index.js";
import { HopframeLangChainCallback } from "../src/integrations/langchainjs.js";
import { wrapMastraTool } from "../src/integrations/mastra.js";
import { wrapMCPClient, type MCPSendable } from "../src/integrations/mcp.js";

interface CapturedBody {
  protocol?: string;
  direction?: string;
  action?: string;
  severity?: string;
  agent_run_id?: string;
  counterparty?: string;
  message?: { method?: string; params?: unknown; result?: unknown };
  findings?: { rule_id: string; description?: string }[];
  latency_micros?: number;
}

function newCaptureClient(): { hf: Hopframe; bodies: CapturedBody[] } {
  const bodies: CapturedBody[] = [];
  const fakeFetch: typeof fetch = async (_url, init: any) => {
    bodies.push(JSON.parse(init.body));
    return new Response(JSON.stringify({ seq: bodies.length, hash: "x" }), { status: 202 });
  };
  const hf = new Hopframe({
    baseURL: "http://localhost:7090",
    sensorID: "ts-test",
    fetchImpl: fakeFetch,
    flushIntervalMs: 100000,
  });
  return { hf, bodies };
}

test("HopframeLangChainCallback emits inbound on toolStart and outbound on toolEnd", async () => {
  const { hf, bodies } = newCaptureClient();
  const cb = new HopframeLangChainCallback({ hopframe: hf, runID: "run-lc-1" });
  cb.handleToolStart({ name: "fetch" }, "https://example.com");
  cb.handleToolEnd("ok body");
  await hf.flushNow();

  assert.equal(bodies.length, 2);
  assert.equal(bodies[0].direction, "inbound");
  assert.equal(bodies[0].agent_run_id, "run-lc-1");
  assert.equal(bodies[0].message?.method, "tools/call");
  assert.equal((bodies[0].message?.params as any).name, "fetch");
  assert.equal(bodies[1].direction, "outbound");
  assert.equal(bodies[1].agent_run_id, "run-lc-1");
  await hf.close();
});

test("HopframeLangChainCallback handleToolError emits a high-severity finding", async () => {
  const { hf, bodies } = newCaptureClient();
  const cb = new HopframeLangChainCallback({ hopframe: hf, runID: "run-lc-2" });
  cb.handleToolError(new Error("upstream 500"));
  await hf.flushNow();

  assert.equal(bodies.length, 1);
  assert.equal(bodies[0].action, "warn");
  assert.equal(bodies[0].severity, "high");
  assert.ok(bodies[0].findings && bodies[0].findings.length === 1);
  assert.equal(bodies[0].findings![0].rule_id, "langchainjs.tool_error");
  assert.equal(bodies[0].findings![0].description, "upstream 500");
  await hf.close();
});

test("HopframeLangChainCallback mints a run id when none is supplied", async () => {
  const { hf, bodies } = newCaptureClient();
  const cb = new HopframeLangChainCallback({ hopframe: hf });
  cb.handleToolStart({ name: "fetch" }, "in");
  cb.handleToolEnd("out");
  await hf.flushNow();

  const run1 = bodies[0].agent_run_id;
  const run2 = bodies[1].agent_run_id;
  assert.ok(run1);
  assert.equal(run1, run2);
  assert.match(run1!, /^run-/);
  await hf.close();
});

test("wrapMastraTool emits around execute and surfaces the original return value", async () => {
  const { hf, bodies } = newCaptureClient();
  const tool = {
    id: "search",
    execute: async (ctx: { context: unknown }) => ({ hits: 3, ctx }),
  };
  const wrapped = wrapMastraTool(tool, { hopframe: hf, agentRunID: "run-mastra-1" });
  const result = (await wrapped.execute!({ context: { query: "hopframe" } })) as { hits: number };

  assert.equal(result.hits, 3);
  await hf.flushNow();
  assert.equal(bodies.length, 2);
  assert.equal(bodies[0].direction, "inbound");
  assert.equal(bodies[1].direction, "outbound");
  assert.equal(bodies[1].agent_run_id, "run-mastra-1");
  assert.deepEqual(bodies[1].message?.result, { hits: 3, ctx: { context: { query: "hopframe" } } });
  await hf.close();
});

test("wrapMastraTool emits a warn-severity event on thrown error and rethrows", async () => {
  const { hf, bodies } = newCaptureClient();
  const tool = {
    id: "broken",
    execute: async () => {
      throw new Error("boom");
    },
  };
  const wrapped = wrapMastraTool(tool, { hopframe: hf, agentRunID: "run-mastra-2" });
  await assert.rejects(() => wrapped.execute!({ context: {} }), /boom/);
  await hf.flushNow();

  assert.equal(bodies.length, 2);
  assert.equal(bodies[1].action, "warn");
  assert.equal(bodies[1].severity, "high");
  assert.equal(bodies[1].findings![0].rule_id, "mastra.tool_error");
  await hf.close();
});

test("wrapMastraTool returns the original tool unchanged when execute is missing", () => {
  const { hf } = newCaptureClient();
  const tool = { id: "noop" };
  const wrapped = wrapMastraTool(tool, { hopframe: hf });
  assert.equal(wrapped, tool);
});

test("wrapMCPClient observes send() with a request and a response event", async () => {
  const { hf, bodies } = newCaptureClient();
  const transport: MCPSendable = {
    send: async (msg) => ({ jsonrpc: "2.0", id: msg.id, result: { tools: [] } }),
  };
  const wrapped = wrapMCPClient(transport, {
    hopframe: hf,
    agentRunID: "run-mcp-1",
    counterparty: "github-mcp",
  });
  await wrapped.send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  await hf.flushNow();

  assert.equal(bodies.length, 2);
  assert.equal(bodies[0].direction, "inbound");
  assert.equal(bodies[0].counterparty, "github-mcp");
  assert.equal(bodies[0].message?.method, "tools/list");
  assert.equal(bodies[1].direction, "outbound");
  // Response carries no method, only result.
  assert.equal((bodies[1].message?.result as any).tools.length, 0);
  await hf.close();
});

test("wrapMCPClient emits a transport_error finding on a thrown send", async () => {
  const { hf, bodies } = newCaptureClient();
  const transport: MCPSendable = {
    send: async () => {
      throw new Error("connection refused");
    },
  };
  const wrapped = wrapMCPClient(transport, { hopframe: hf, agentRunID: "run-mcp-2" });
  await assert.rejects(() => wrapped.send({ jsonrpc: "2.0", id: 1, method: "tools/list" }), /connection refused/);
  await hf.flushNow();

  assert.equal(bodies.length, 2);
  assert.equal(bodies[1].action, "warn");
  assert.equal(bodies[1].findings![0].rule_id, "mcp.adapter.transport_error");
  assert.equal(bodies[1].findings![0].description, "connection refused");
  await hf.close();
});

test("wrapMCPClient leaves non-send properties untouched", () => {
  const { hf } = newCaptureClient();
  const transport = { send: async () => ({}), close: () => "closed" } as unknown as MCPSendable;
  const wrapped = wrapMCPClient(transport, { hopframe: hf });
  assert.equal(typeof (wrapped as any).close, "function");
  assert.equal((wrapped as any).close(), "closed");
});

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { Hopframe, newEvent } from "../src/index.js";
import { wrapAISDKTool } from "../src/integrations/ai-sdk.js";

test("newEvent populates schema and id", () => {
  const ev = newEvent("s1", { protocol: "mcp", direction: "inbound" });
  assert.equal(ev.sensor_id, "s1");
  assert.equal(ev.schema, "hopframe.event/v1");
  assert.match(ev.event_id, /^ev-[0-9a-f]{24}$/);
  assert.equal(ev.protocol, "mcp");
});

test("Hopframe.emit buffers and flush sends with bearer", async () => {
  const seen: { url: string; init?: RequestInit }[] = [];
  const fakeFetch: typeof fetch = async (url: any, init?: any) => {
    seen.push({ url: String(url), init });
    return new Response(JSON.stringify({ seq: seen.length, hash: "abc" }), {
      status: 202,
      headers: { "content-type": "application/json" },
    });
  };
  const hf = new Hopframe({
    baseURL: "http://localhost:7090",
    token: "tok",
    sensorID: "tester",
    fetchImpl: fakeFetch,
    flushIntervalMs: 100000, // disable timer-driven flush
  });
  hf.emit({ protocol: "mcp", direction: "inbound", message: { method: "tools/list" } });
  hf.emit({ protocol: "mcp", direction: "outbound", message: { method: "tools/list" } });
  await hf.flushNow();
  assert.equal(seen.length, 2);
  assert.equal(seen[0].url, "http://localhost:7090/v1/events");
  const headers = (seen[0].init?.headers as Record<string, string>) ?? {};
  assert.equal(headers["Authorization"], "Bearer tok");
  await hf.close();
});

test("Hopframe.emit retries on 5xx and gives up after maxRetries", async () => {
  let calls = 0;
  const fakeFetch: typeof fetch = async () => {
    calls++;
    return new Response("nope", { status: 503 });
  };
  let droppedCount = 0;
  const hf = new Hopframe({
    baseURL: "http://localhost:7090",
    sensorID: "tester",
    fetchImpl: fakeFetch,
    flushIntervalMs: 100000,
    maxRetries: 2,
    onDrop: (n) => { droppedCount += n; },
  });
  hf.emit({ protocol: "mcp", direction: "inbound" });
  await hf.flushNow();
  assert.equal(droppedCount, 1);
  assert.equal(calls, 3); // initial + 2 retries
  await hf.close();
});

test("Hopframe.emit does not retry on 4xx (excluding 429)", async () => {
  let calls = 0;
  const fakeFetch: typeof fetch = async () => {
    calls++;
    return new Response("bad", { status: 400 });
  };
  let dropped = 0;
  const hf = new Hopframe({
    baseURL: "http://localhost:7090",
    sensorID: "tester",
    fetchImpl: fakeFetch,
    flushIntervalMs: 100000,
    maxRetries: 5,
    onDrop: (n) => { dropped += n; },
  });
  hf.emit({ protocol: "mcp", direction: "inbound" });
  await hf.flushNow();
  assert.equal(calls, 1);
  assert.equal(dropped, 1);
  await hf.close();
});

test("wrapAISDKTool emits inbound + outbound events around execute", async () => {
  const events: string[] = [];
  const fakeFetch: typeof fetch = async (_, init: any) => {
    const body = JSON.parse(init.body);
    events.push(body.direction);
    return new Response(JSON.stringify({ seq: events.length, hash: "x" }), { status: 202 });
  };
  const hf = new Hopframe({
    baseURL: "http://localhost:7090",
    sensorID: "ts",
    fetchImpl: fakeFetch,
    flushIntervalMs: 100000,
  });
  const wrapped = wrapAISDKTool(
    { execute: async (args: any) => ({ ok: true, in: args }) },
    { hopframe: hf, agentRunID: "run-1" },
  );
  await wrapped.execute!({ q: "hi" });
  await hf.flushNow();
  assert.deepEqual(events, ["inbound", "outbound"]);
  await hf.close();
});

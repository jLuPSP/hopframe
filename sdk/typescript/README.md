# `@hopframe/sdk`

Hopframe TypeScript SDK. Emits agent traffic events from Node-based MCP clients, MCP servers, and JS agent frameworks (Vercel AI SDK, LangChainJS, Mastra) to a Hopframe control plane.

This is the JS counterpart to the Python SDK at `sdk/python`. The base layer is dependency-free; framework adapters import their own deps lazily.

## Install

> **Coming soon to npm.** The Python SDK (`hopframe`) ships to PyPI first; the
> `@hopframe/sdk` npm release is on the way. Until then, link it from the repo:

```bash
git clone https://github.com/jLuPSP/hopframe.git
cd hopframe/sdk/typescript
npm install
npm run build
npm link            # makes @hopframe/sdk available to local projects
```

Then in your project: `npm link @hopframe/sdk`.

Once it is published to npm (coming soon):

```bash
npm install @hopframe/sdk
```

## Use the client directly

```ts
import { Hopframe } from "@hopframe/sdk";

const hf = new Hopframe({
  baseURL: "http://hopframe.acme.svc.cluster.local:7090",
  token: process.env.HOPFRAME_API_TOKEN,
  sensorID: "checkout-agent",
  tenantID: "acme",
});

hf.emit({
  protocol: "mcp",
  direction: "inbound",
  agent_run_id: "run-abc",
  message: { method: "tools/list" },
});

// Before process exit:
await hf.flushNow();
await hf.close();
```

## Vercel AI SDK

```ts
import { generateText } from "ai";
import { Hopframe } from "@hopframe/sdk";
import { wrapAISDKTools } from "@hopframe/sdk/ai-sdk";

const hf = new Hopframe({ baseURL: "http://localhost:7090" });

const tools = wrapAISDKTools(
  {
    fetch: { execute: async ({ url }) => fetch(url).then(r => r.text()) },
  },
  { hopframe: hf, agentRunID: "run-abc" },
);

await generateText({ model, tools, prompt: "..." });
```

## LangChainJS

```ts
import { Hopframe } from "@hopframe/sdk";
import { HopframeLangChainCallback } from "@hopframe/sdk/langchainjs";

const hf = new Hopframe({ baseURL: "http://localhost:7090" });
const cb = new HopframeLangChainCallback({ hopframe: hf });

await agent.invoke({ input: "..." }, { callbacks: [cb] });
```

## Mastra

```ts
import { Hopframe } from "@hopframe/sdk";
import { wrapMastraTool } from "@hopframe/sdk/mastra";

const hf = new Hopframe({ baseURL: "http://localhost:7090" });

const tool = wrapMastraTool(myTool, { hopframe: hf, agentRunID: "run-abc" });
```

## MCP transport (advanced)

```ts
import { Hopframe } from "@hopframe/sdk";
import { wrapMCPClient } from "@hopframe/sdk/mcp";

const hf = new Hopframe({ baseURL: "http://localhost:7090" });
const transport = wrapMCPClient(rawTransport, {
  hopframe: hf,
  counterparty: "github-mcp",
});
```

## Notes

- Events are buffered in memory and flushed on a 1-second timer or when the buffer reaches `batchSize` (default 64).
- Send retries on 5xx and 429 with exponential backoff up to `maxRetries` (default 3); 4xx errors are dropped immediately.
- The SDK does not run the four-layer detection pipeline; that lives in the Go sensor. Events emitted from this SDK land on the same control-plane timeline and are matched against operator policies for visibility, but the disposition is advisory in this code path.
- Wire schema and event shapes mirror `pkg/event/event.go`. Three implementations (Go, Python, TS) of the same shape so any producer lands on the same timeline.

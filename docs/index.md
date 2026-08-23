# Deploy Hopframe

One engine, two ways to run it. Pick the path that matches where you control the traffic.

> **Alpha.** Start with evaluation traffic. Validate detection coverage and failure modes before a regulated workload. Status and caveats are in the [README](../README.md).

## Inline: on the wire

You control the MCP or A2A server. Run Hopframe in front of it. The agent and the server don't change; Hopframe inspects every JSON-RPC message between them.

```bash
git clone https://github.com/jLuPSP/hopframe.git
cd hopframe

# Go 1.25+
make run UPSTREAM=http://your-mcp-server:8080

# or Docker (no Go)
UPSTREAM=http://your-mcp-server:8080 docker compose up
```

Repoint your agent at `http://127.0.0.1:7080/mcp` instead of your MCP's URL. Open `http://127.0.0.1:7090` for the console.

`mcp-gateway` (fronts several MCP servers) and the Envoy `mcp-extauthz` adapter are variants of this path, in [`cmd/`](https://github.com/jLuPSP/hopframe/tree/main/cmd).

## SDK: inside your agent

Traffic can't be rerouted but you own the agent code. The SDK hooks your agent's tool calls and emits events to a Hopframe control plane. Observes and advises; it does not hard-block.

The SDKs are source-only for now, not on PyPI or npm:

- Python: `pip install "hopframe @ git+https://github.com/jLuPSP/hopframe.git@main#subdirectory=sdk/python"`
- TypeScript: build and link from [`sdk/typescript`](https://github.com/jLuPSP/hopframe/tree/main/sdk/typescript)

## How to pick

- **Inline** when you control the endpoint and want hard-blocking with no code changes.
- **SDK** when the runtime is managed and you want agent-side visibility, advisory only.

Both write to the same hash-chained audit log. What Hopframe catches, its status, and the full run modifiers are in the [README](../README.md).

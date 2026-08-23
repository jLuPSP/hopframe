# Deploy Hopframe

One engine, two ways to run it. Pick the path that matches where you control the traffic. Both converge on the same control plane and the same audit log.

## Quick start

````bash
make demo    # cinematic story, bundled stubs, no setup, ~30 seconds
````

Then the real ones below.

## Which path

| You control... | Path | Effect |
| --- | --- | --- |
| The MCP or A2A server | [Inline, in the data path](#inline-in-the-data-path) | Hard-blocking, no agent code changes, full fidelity |
| The agent (managed runtime) | [SDK, inside your agent](#sdk-inside-your-agent) | Advisory, agent-side visibility, no rerouting |

## Inline: in the data path

You control the endpoint. Run Hopframe in front of it. The agent and the server do not change; Hopframe inspects every JSON-RPC message between them and blocks the ones its policy says to block.

````bash
git clone https://github.com/jLuPSP/hopframe.git
cd hopframe

# Go 1.25+
make run UPSTREAM=http://your-mcp-server:8080

# or Docker (no Go required; the multi-stage Dockerfile compiles inside the build)
UPSTREAM=http://your-mcp-server:8080 docker compose up
````

Repoint your agent at `http://127.0.0.1:7080/mcp` instead of your MCP's URL. Open `http://127.0.0.1:7090` for the operator UI.

**Variants of this path**, all in [`cmd/`](https://github.com/jLuPSP/hopframe/tree/main/cmd):

- `mcp-gateway` fronts several MCP upstreams at one address, sharing quarantine and taint state across routes.
- `mcp-extauthz` attaches the same pipeline to an Envoy-style gateway (Envoy, Istio, Gloo, Emissary) as an external-authorization service. Request-side only.
- `mcp-stdio-sensor` / `a2a-sensor` / the combined `sensor` cover the stdio and A2A surfaces.

### Docker Compose shapes

| Command | What it boots |
| --- | --- |
| `docker compose up` | Control plane + MCP sensor in front of your MCP (`UPSTREAM`). |
| `UPSTREAM=... A2A_UPSTREAM=... docker compose --profile a2a up` | Adds an A2A sensor on `:7081`. |
| `docker compose --profile postgres up` | Bundled Postgres for the audit chain. |
| `HOPFRAME_STORE_DSN=postgres://... docker compose up` | Managed Postgres (Cloud SQL, RDS, Azure, Aiven, Neon, Supabase). |

Set `HOPFRAME_STORE_DSN` to use a Postgres backend for the audit chain instead of the local NDJSON file. Rotation runs hourly; retention defaults to 90 days, configurable.

### Kubernetes (Helm)

````bash
helm upgrade --install hopframe ./deploy/helm/hopframe \
  --namespace hopframe --create-namespace \
  --set mcpSensor.upstream.url=http://my-mcp-server:8080 \
  --set image.tag=0.1.0
````

This deploys the control plane as a `StatefulSet` with a `PersistentVolumeClaim` for the append-only event log (retention default 90d), plus the MCP sensor forwarding to `mcpSensor.upstream.url`. See the chart's [README](https://github.com/jLuPSP/hopframe/tree/main/deploy/helm/hopframe) and the [Configuration](configuration.md) page for the full value set.

## SDK: inside your agent

Traffic cannot be rerouted but you own the agent code. The SDK hooks your agent's tool calls and emits events to a Hopframe control plane of your choice. It observes and advises; it does not hard-block and does not reroute.

The SDKs are source-only for now, not on PyPI or npm:

- **Python**: `pip install "hopframe @ git+https://github.com/jLuPSP/hopframe.git@main#subdirectory=sdk/python"`
- **TypeScript**: build and link from [`sdk/typescript`](https://github.com/jLuPSP/hopframe/tree/main/sdk/typescript)

Point the SDK at a control plane (`HOPFRAME_EMITTER_URL` or constructor), and events flow into the same audit log and UI as inline sensors.

## The control plane (one way, both paths need it)

Both paths emit the same `hopframe.event/v1` events to a control plane. Run it however you like: `docker compose up`, the Helm chart, or the `control-plane` binary. It serves the operator UI on `:7090`, the `/v1/*` API, and holds policies, sensors, users, tokens, and the audit chain.

## Config keys, secrets, and defaults

Environment variables set the control plane's behavior (listen address, retention, OIDC, Rekor, rate limits, TLS). The sensor reads a YAML file (`examples/config/sensor.yaml`) for rules, emitter, and policy. The Helm chart surfaces the same knobs as values. Full reference: [Configuration](configuration.md).

## After you deploy

1. Open `http://127.0.0.1:7090`, or run `hopframe stats` and `hopframe verify` to confirm the chain is healthy.
2. Point your agent at the sensor (inline) or wire the SDK (agent-side).
3. Confirm events appear in the UI and the chain advances. `hopframe events list` is the quick check.
4. Set `SECURE=1` (or the Helm auth values) before real traffic. See [Security](security.md).

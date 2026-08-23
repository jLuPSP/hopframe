# Install

One binary set runs every surface. The same engine inspects MCP and A2A traffic wherever you put it, and you can move between surfaces without reinstalling. Everything ships in this repo under one license; there are no paid tiers.

!!! warning "Alpha"
    Start with evaluation traffic. Validate the detection coverage and failure modes before using Hopframe for a regulated workload. High availability and SOC 2 attestation are not shipped; see the [roadmap](roadmap.md).

Pick a placement from [Where it runs](surface-matrix.md): the **inline sensor** on one MCP/A2A wire, the **gateway** in front of several MCP servers, **ext_authz** behind an existing gateway, or the **SDK** inside your agent. Deploy differently, same engine.

## Locally, to try or run it

Need Go 1.25+, or just Docker. Either path gives a control plane at `:7090` and a sensor at `:7080/mcp`.

```bash
git clone https://github.com/jLuPSP/hopframe.git
cd hopframe

# with Go
make run UPSTREAM=http://your-mcp-server:8080

# or with Docker (no Go)
UPSTREAM=http://your-mcp-server:8080 docker compose up
```

Point your agent at `http://127.0.0.1:7080/mcp` instead of your MCP's URL. The agent and the MCP server don't change. `make demo` replays the attack story instead of your traffic.

## As your front door (Kubernetes)

The [Helm chart](https://github.com/jLuPSP/hopframe/blob/main/deploy/helm/hopframe/README.md) deploys the control plane and an MCP sensor on Kubernetes. You set the upstream MCP URL and an image tag; the chart wires the service, storage, and secret. Values reference is in the chart README.

```bash
helm upgrade --install hopframe ./deploy/helm/hopframe \
  --namespace hopframe --create-namespace \
  --set mcpSensor.upstream.url=http://your-mcp-server:8080
```

## Where the app-specific bits live

- **An existing Envoy-style gateway (Istio, Gloo, Emissary):** run `cmd/mcp-extauthz` and wire it as an authorization service. Request-side only; it never sees tool replies.
- **A managed agent runtime:** see [Vertex AI Agent Engine](agent-engine.md) for the vendor walkthrough. Prebuilt binaries and multi-arch container images for each release are on the [Releases](https://github.com/jLuPSP/hopframe/releases) page.

Configuration is environment variables. `docs/cli.md` lists them and the flags; the SDK READMEs cover the code surfaces. Run the same binary and turn on what you need.

## What each env does (turn them on as you need)

- `HOPFRAME_API_TOKEN` adds bearer auth on `/v1/*`.
- `HOPFRAME_SIGNING_KEY` adds per-record Ed25519 signatures.
- `HOPFRAME_TENANT_TOKENS` (`token:tenantA,...`) scopes reads and pins writes to a tenant.
- `HOPFRAME_ROLE_TOKENS` (`token:viewer,...`) binds tokens to roles.
- `HOPFRAME_OIDC_*` enables SSO; `HOPFRAME_REKOR_URL` anchors the chain to Sigstore.
- `HOPFRAME_LLM_JUDGE_URL` enables the on-demand LLM adjudication layer.
- `HOPFRAME_STORE_DSN=postgres://...` swaps the file log for Postgres.

Everything not listed here is covered in [cli.md](cli.md) and [operations.md](operations.md).

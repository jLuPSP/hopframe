# Hopframe architecture

This document describes how Hopframe's components fit together, the data flows between them, and the design choices behind each piece. Read it after the [README](https://github.com/jLuPSP/hopframe/blob/main/README.md), before contributing significant changes.

---

## Components at a glance

```mermaid
flowchart LR
    Agent([agent])
    SDK([non-MCP frameworks<br/>LangChain / LangGraph<br/>CrewAI / OpenAI])

    subgraph Sensor [sensor]
        direction TB
        S[mcp-sensor / mcp-stdio-sensor / a2a-sensor<br/>HTTP / stdio / SSE]
    end

    Upstream[upstream<br/>MCP server or A2A peer]

    subgraph CP [control plane]
        direction LR
        Ingest[/v1/* ingest]
        Store[chain store<br/>SHA-256 hash chain<br/>Ed25519 signing]
        Hub[SSE hub]
        Behavior[behavior detector]
        Exporters[exporters<br/>webhook / Splunk HEC]
        Ingest --> Store --> Hub
        Ingest --> Behavior
        Ingest --> Exporters
    end

    Verify[/v1/verify]
    UI[live UI<br/>/dashboard /audit /records]

    Agent -- protocol traffic --> Sensor
    Sensor -- forwards --> Upstream
    Upstream -- response --> Sensor
    Sensor -- inspected --> Agent
    Sensor -- events HTTP / NDJSON spool --> Ingest
    SDK -- /v1/events --> Ingest
    Store --> Verify
    Hub --> UI
```

Three flavours of producer feed the same control-plane log:

1. **`mcp-sensor`** (HTTP). Reverse proxy in front of an HTTP MCP server. Inspects the request, applies the pipeline, forwards to upstream, then inspects the response (or stream).
2. **`mcp-stdio-sensor`** (stdio). Spawns the upstream as a child process and parses newline-delimited JSON-RPC over the pipes.
3. **`a2a-sensor`** (HTTP). Same shape as the MCP sensor, but speaks the A2A task envelope and exposes an agent-card validation hook.
4. **`hopframe-py`** SDK. Python package that emits events directly from agent-framework callbacks (LangChain, LangGraph, CrewAI, OpenAI Assistants).

All four emit the same `event.Event` JSON shape to the control plane.

---

## The detection pipeline

Layered defense, ordered by cost:

| Layer | What | Where | Latency | Coverage |
|---|---|---|---|---|
| 1 | Regex rule packs (RE2) | `pkg/ruleset` | sub-5µs | known signatures, tool descriptions, credential formats |
| 2 | Heuristic feature-density classifier | `pkg/detect/heuristic.go` | sub-30µs | paraphrased / novel injection-shaped content |
| 3 | LLM judge | `pkg/detect/llmjudge` | 300-1500ms | high-stakes calls the lower layers are unsure about; opt-in via `HOPFRAME_LLM_JUDGE_URL` |
| 4 | Behavioral anomaly | `control-plane/behavior` | continuous | rate spikes, novel-peer-with-high-severity, findings-rate drift |

The pipeline composes detectors via the `detect.Detector` interface. A `Verdict` accumulates findings; the `ModeResolver` (typically `ruleset.Ruleset.HighestMode`) walks findings and picks the strongest mode (monitor / warn / block).

A few cross-cutting primitives sit alongside the layers:

- **`internal/quarantine`.** When a `tools/list` description triggers a high or critical finding, the named tool is added to a TTL-bounded quarantine. Subsequent `tools/call` to that tool short-circuit-block regardless of payload content.
- **`pkg/taint`.** MCP `tools/call` results are tagged with shingle fingerprints and source metadata. A2A task messages on the same `agent_run_id` are checked for reuse and blocked when a non-allowlisted peer would receive tagged data.
- **`internal/taskstate`.** A2A task lifecycles tracked across calls. Drift, invalid transitions, and counterparty changes raise findings inline.
- **`internal/counterparty`.** Per-peer reputation registry with severity-weighted scoring, time decay, and threshold alarms.

---

## Cross-protocol correlation

Sensors propagate `X-Hopframe-Agent-Run-Id`. If the inbound request carries one, the sensor uses it. Otherwise, it generates one with a `run-` prefix. The header rides through to the upstream and back to the client. The control plane indexes events by this id. Events from MCP, A2A, behavior, and the Python SDK for one agent run all land on the same forensic timeline (`/v1/agent-runs/{id}/timeline`).

This mechanism **automatically correlates MCP and A2A traffic for the same agent run**. No competitor offers this because no competitor sits on both protocols.

---

## The audit log

`control-plane/store` is an append-only NDJSON file with SHA-256 hash chaining. Each record's hash includes the previous record's hash. The design provides these guarantees:

1. **Tamper detection.** Modifying any record visibly breaks the chain the next time `Verify()` walks it.
2. **Signed exports.** Every CSV / NDJSON download from `/v1/events.{ndjson,csv}` carries a chain-proof trailer (head hash, export timestamp, seq range). The trailer binds the file to a specific point in chain history.
3. **Continuous trust signal.** The UI's *integrity verified* badge polls `/v1/verify` every 60s. It goes red when broken.

Retention rotation drops records older than the configured window. A sidecar `<log>.genesis` file preserves chain integrity after rotation by recording the prev-hash of the first surviving record. `Verify()` uses that value as the chain-start anchor.

---

## Wire formats

Hopframe tries to be format-agnostic at the edges so it works with whatever the deployment uses:

- **HTTP MCP.** POST JSON-RPC over HTTP request/response.
- **stdio MCP.** Newline-delimited JSON-RPC on stdin/stdout. The sensor *is* a stdio MCP server from the client's point of view, with the upstream as its child process.
- **Streamable HTTP / SSE.** When upstream returns `Content-Type: text/event-stream`, the proxy switches to chunk-forwarding mode. Each `data:` event is parsed and run through the pipeline. Poisoned chunks are replaced with a `hopframe-blocked` event in-stream.
- **A2A v1.** POST task envelopes plus `GET /.well-known/agent.json` for card discovery and signature verification.
- **JSON-RPC batching.** `mcp.ParseBatch` handles top-level arrays of envelopes; detection applies per element.

---

## Configuration

YAML at the file boundary, env vars override at runtime. See `internal/config/config.go`:

- `sensor`: id, tenant
- `upstream`: URL and timeout (HTTP shape)
- `listen`: bind address
- `rules.dirs`: directories of YAML rule packs
- `emitter.{sink,url,path}`: stdout / file / http
- `emitter.spool_*`: durable replay during control-plane outage
- `emitter.tls.*`: mTLS to the control plane
- `policy.fail_open`: what to do on pipeline error

Operational env vars on the control plane:

- **Auth.** `HOPFRAME_API_TOKEN` (single bearer), `HOPFRAME_TENANT_TOKENS` (token:tenant pairs), `HOPFRAME_ROLE_TOKENS` (token:role pairs), `HOPFRAME_USERS_PATH` (file-backed accounts), `HOPFRAME_BOOTSTRAP_ADMIN`, `HOPFRAME_TOKENS_PATH` (API tokens minted via the API).
- **OIDC.** `HOPFRAME_OIDC_ISSUER`, `HOPFRAME_OIDC_AUDIENCE`, `HOPFRAME_OIDC_CLIENT_ID`, `HOPFRAME_OIDC_CLIENT_SECRET`. All four enable SSO at `/auth/login`.
- **Cryptographic audit.** `HOPFRAME_SIGNING_KEY` (Ed25519 seed), `HOPFRAME_REKOR_URL` (Sigstore witness).
- **Policies + content + fleet.** `HOPFRAME_POLICY_PATH`, `HOPFRAME_CONTENT_ROOT`, `HOPFRAME_SENSOR_FLEET`.
- **Detection.** `HOPFRAME_LLM_JUDGE_URL`.
- **Limits.** `HOPFRAME_RATE_LIMIT_RPS` (per-IP).
- **Exporters.** `HOPFRAME_WEBHOOK_URL` + `HOPFRAME_WEBHOOK_SECRET` + `HOPFRAME_WEBHOOK_MIN_SEVERITY`, `HOPFRAME_SPLUNK_URL` + `HOPFRAME_SPLUNK_TOKEN` + `HOPFRAME_SPLUNK_INDEX`.

Sensor-side env vars: `HOPFRAME_API_TOKEN` (bearer to the control plane), `HOPFRAME_TRUST_DIR` (A2A agent-card signature trust store), `HOPFRAME_CONTROL_PLANE_URL` (heartbeat target).

---

## Why this shape

A few decisions worth documenting:

- **Inline mesh.** We sit on the wire because attacks happen at runtime. A static scanner can identify what a tool description *might* do. Only an inline mesh can stop what it *is* doing.
- **Cross-protocol from day one.** Everyone else supports one protocol. Confused-deputy and capability-laundering attacks live on the cross-protocol surface.
- **Open content registry.** The rule packs are YAML, live in the repo, and accept contributions by PR. Cloudflare WAF rules, OWASP, and ClamAV all demonstrate that open detection content creates a stronger long-term moat than closed content.
- **Cryptographic accountability.** A hash-chained log plus signed exports turns Hopframe into an evidence-grade tool for compliance-grade buyers.
- **Layered detection at cost-aware speeds.** Regex runs first (5µs), the classifier runs second (30µs), the optional LLM judge follows (500ms), and behavioral detection runs centrally (continuous). Most competitors run a single layer at the wrong cost.

---

## Where this is going

This document describes the v0.1 alpha shape. The three pillars (editable policy plane, enterprise control plane, cryptographic audit-grade evidence) are all in-tree. The remaining work is mostly operational. The file-backed audit log moves to a Postgres-backed HA control plane while preserving hash-chain semantics. That work is Phase 2C in [roadmap.md](roadmap.md). It moves the product from "alpha that runs on a laptop" to "regulated buyer can run this in production at scale." Other roadmap items include long-term archival to object storage, cryptographic per-tenant scoping (separate signing keys per tenant), and a SOC 2 Type II audit trail for the hosted offering.

## Where to look in code

| Question | Path |
|---|---|
| How does an MCP request flow through the sensor? | `internal/proxy/proxy.go::ServeHTTP` |
| How does stdio MCP work? | `internal/stdioproxy/stdioproxy.go::Run` |
| How is a YAML rule compiled and matched? | `pkg/ruleset/ruleset.go::compile`, `Detect` |
| How is the heuristic classifier scored? | `pkg/detect/heuristic.go::scoreField` |
| How does cross-protocol taint work? | `pkg/taint/taint.go`, `internal/pipeline/pipeline.go::TagMCPResult / CheckA2ALeak` |
| How does the chain stay intact across rotation? | `control-plane/store/retention.go::Rotate` + `<log>.genesis` |
| How does the live UI talk to the backend? | `control-plane/api/ui.html` (SSE on `/v1/events/stream`) |
| How are exports signed? | `control-plane/api/api.go::handleEventsNDJSON / handleEventsCSV` |

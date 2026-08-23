# How Hopframe works

Hopframe is a security mesh for the protocol traffic agents actually emit. It sits on the MCP and A2A wires and inspects every JSON-RPC message before it lands: decide allow, warn, or block, then write the outcome to a tamper-evident audit log. It never reads the user prompt or the model's tokens. It only sees the messages between an agent and its tools.

That is the whole model: **one engine, run where you control the traffic**. The same detection pipeline powers every surface, from a single inline sensor to an Envoy authorization service to an SDK inside your agent.

## Why the protocol wire

Model-boundary guardrails watch the prompt going into an LLM and the response coming back. Agents have other wires that no prompt-layer filter ever sees:

- The **tool description** (`tools/list`) an MCP server serves, which can carry instructions of its own.
- The **tool result** that comes back, which can contain a leaked key or a forwarding directive.
- The **A2A task envelope** between agents, which can lie about state or change counterparties mid-task.
- The **cross-protocol path**: data read over one wire leaving over the other.

Hopframe inspects that traffic inline, so a poisoned description is caught before the model reads it and a leak is caught before it leaves.

## What it catches

A shipped detection catalog of **58 rules across 6 categories**, every one inspectable in the repo under `content/` and licensed Apache 2.0:

| Category | Word |
| --- | --- |
| `tool-poisoning` | `tools/list` descriptions that issue instructions, rug-pull, or redirect the agent |
| `prompt-injection` | injection in tool arguments and results, paraphrased overrides, encoded payloads |
| `credential-exfiltration` | AWS / GCP / GitHub / Slack / OpenAI / Anthropic keys, PEM private keys |
| `pii-leakage` | SSN, card, IBAN, and bulk-email shapes, per tenant |
| `policy` | behavior-level policy findings on the control plane |
| `a2a-card` | agent-card and skill-description checks at A2A discovery |

Each rule is a RE2 pattern bound to a severity (`info` to `critical`), a default mode (`warn` or `block`), optionally a specific protocol method or direction, and a field scope written as globs over the inspectable message tree. Rules are case-insensitive by default and carry a calibrated confidence that is attached to every finding. A rule's authoritative fields are hashed at compile time, so a finding can cite the exact SHA-256 of the rule that produced it and be re-verified offline.

```yaml
# content/credential-exfiltration/core.yaml (abridged)
category: credential-exfiltration
rules:
  - id: ce.core.aws_secret_key
    description: AWS secret access key heuristic (label + 40-char base64).
    severity: critical
    mode: block
    fields: ["params.**", "result.**"]
    patterns: ['aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+]{40}["']?']
```

## How a message is inspected

Every message runs through the same four-stage pipeline. Traffic exits as soon as a stage is confident, so the common case is decided by the cheap stages and the expensive stage runs only on the ambiguous middle.

| Stage | What runs | Cost (measured) |
| --- | --- | --- |
| 1. Regex rule packs | The 58-rule catalog, compiled to RE2 | sub-5µs |
| 2. Heuristic classifier | Feature-density scoring for injection-shaped content the regex missed | sub-30µs |
| 3. LLM judge | Optional, runs only on the uncertain band between 1 and 2 | 300-1500ms |
| 4. Behavioral anomaly | On the control plane, over time and across messages | continuous |

Before any stage matches, Hopframe normalizes the input: NFKC Unicode normalization, zero-width and homoglyph runes stripped, and nested base64 decoded recursively. The obvious evasions therefore fail before detection even runs.

**Quarantine** ties stages together. A `tools/list` response that trips stage 1 or 2 quarantines the named tool; the next `tools/call` to it short-circuits at the sensor, no repeat analysis needed.

## The differentiator: cross-protocol taint

Separate content filters on the MCP wire and the A2A wire cannot catch a value that is read over one and exfiltrated over the other. Hopframe can, because one process holds the shared state.

When an MCP `tools/call` result comes back, Hopframe fingerpints every string value it inspects and files the fingerprints under that agent run. When the agent later emits an A2A task toward a peer, Hopframe compares the outgoing bytes against the tagged set for that run. A match is blocked on *provenance*, regardless of whether the bytes look like a credential.

Fingerprinting is **shingling**: the value is hashed over a sliding 24-byte window with SHA-256, producing a set of fingerprints. Two values match when their shingle sets overlap, which is the standard near-duplicate test. It survives re-encoding and near-exact rewording, and it is fast enough to run on the forwarding hot path.

The tracker is per-agent-run and bounded: 128 tagged values per run, 4096 runs in the live table, idle runs evicted by TTL and the oldest dropped first. A shared backend lets taints minted on one sensor be matched on another, closing the split-sensor and multi-replica gap. The wire moves fingerprints, with a short sample attached only for human-readable findings. Registration is asynchronous and best-effort; a missed push falls back to local-only matching, and a full paraphrase escapes this layer by design.

## One event, every surface

Every surface emits the same structured event, schema `hopframe.event/v1`:

```json
{
  "schema": "hopframe.event/v1",
  "event_id": "ev_...",
  "timestamp": "2026-08-21T12:00:00Z",
  "sensor_id": "sensor-a",
  "agent_run_id": "run_...",
  "protocol": "mcp",
  "direction": "outbound",
  "source": "203.0.113.5",
  "destination": "mcp-server-1",
  "message": {"method": "tools/call", "raw": "..."},
  "findings": [{"rule_id": "ce.core.aws_secret_key", "severity": "critical", "field": "result..0.text"}],
  "action": "block",
  "severity": "critical",
  "latency_micros": 42
}
```

Events are append-only, JSON-serializable, and forward-compatible (receivers tolerate unknown fields). The `latency_micros` field records exactly how long the sensor spent on that message. SDKs, the inline sensor, the gateway, and `mcp-extauthz` all feed events into the same control plane, so one timeline holds the MCP read, the A2A send, and every detection in between.

## The audit chain and the evidence

Every decision is recorded in an append-only chain, so a record cannot be silently altered or dropped:

- **SHA-256 hash chain.** Each record's hash includes the previous head, so any edit breaks the chain visibly.
- **Per-record Ed25519 signatures.** `GET /v1/records/{seq}` returns the canonical bytes, the signature, and a Merkle proof. The operator UI verifies the signature in-browser with the Web Crypto API; a single record can be handed to an auditor without revealing the rest (selective disclosure).
- **Sigstore Rekor anchoring.** The chain head can be posted to a Rekor transparency log on demand; the anchor itself is written back into the chain, so the external witness becomes part of the trail.
- **`hopframe-export`.** A standalone binary pulls a window of records, signs each, builds a Merkle root, and writes a manifest plus a `VERIFY.md`. The receiver verifies the bundle offline, with no access to the control plane. That is the shape a compliance auditor can follow.

Every rule also hashes its own authority, and the OTA content manifest serves each rule pack under a SHA-256 header that sensors verify on heartbeat, so the detection logic is as attestable as the log.

## The control plane

All of that sits behind one HTTP API (`/v1/*`) that the UI and the CLI are thin wrappers over:

- **Editable, versioned policies** as first-class resources, resolved by hierarchy (org default → tenant override → sensor override, most-specific wins), with a dry-run preview against the last 1000 events and hot reload on the sensor heartbeat. No binary redeploy.
- **Multi-tenant scoping.** Tokens are bound to a tenant; reads filter and writes pin `tenant_id`. The same binary serves a homelab and a regulated tenant.
- **RBAC roles** (`viewer` / `editor` / `admin` / `owner`) and optional OIDC SSO with JWKS verification.
- **Sensor fleet inventory** with heartbeat, applied-policy version, and drift.
- **Rate limiting** on `/v1/*`, and API tokens minted on demand (only the SHA-256 of the secret persists).
- **Exports** to a webhook or Splunk HEC for SIEM delivery.

## Where you run it

Same engine, two placements, detailed on the [Deploy page](index.md):

- **Inline, on the wire.** `mcp-sensor` / `a2a-sensor` in front of the server you control. The agent and server do not change; you get hard-blocking and full response-side fidelity. `mcp-gateway` fronts several MCP upstreams at one address; `mcp-extauthz` bolts the same pipeline onto an Envoy-style gateway (request-side only, for gateways you already run).
- **SDK, inside your agent.** Hooks your agent's tool calls (LangChain, LangGraph, CrewAI, OpenAI Assistants, Vercel AI SDK, Mastra) and emits events to the control plane. It observes and advises; no hard-block and no rerouting. Source-only today on PyPI and npm.

## Empirically grounded

- **58 detection rules**, Apache 2.0, inspectable and forkable under `content/`.
- **95-case corpus** in `bench/corpus/v1.jsonl`, replayable with `hopframe-bench` for precision/recall and latency budgets, green in CI on every commit.
- **22 Go packages** tested under `-race`, 15 Python tests, 14 TypeScript tests.
- **Measured latency.** ~115k evals/sec on a laptop (p50 ~30µs, p99 ~160µs); the LLM judge adds its 300-1500ms only on the uncertain band.
- Prebuilt binaries for linux / darwin / windows on amd64 / arm64, multi-arch container images, Syft SBOMs, and cosign-signed checksums per release.

## What it deliberately is not

- A model-layer guardrail. It does not inspect prompts or model responses. Layer-1 regex heuristics on tool-result text are the only overlap; run both for their respective surfaces.
- Semantic data-flow analysis. Taint is byte-level, near-duplicate lineage between two protocols, not meaning tracking; a full paraphrase escapes it.
- A certified or magic detector. The corpus is small, so treat its results as a floor and validate against your real traffic. Hopframe is alpha and fits evaluation, a homelab, a small team, or wherever you want hard evidence on agent traffic before you trust it.

This page is the short story. The [Go source](https://github.com/jLuPSP/hopframe/tree/main) is the full one, and [building-hopframe](https://jlu.dev/blog/building-hopframe/) walks through the pipeline and the threat model in prose.

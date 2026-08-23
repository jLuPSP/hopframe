# Where Hopframe runs

Hopframe can observe an agent from its code or inspect traffic on the wire.
Choose a surface based on what you own and whether you need blocking.

There are four ways today, plus one planned.

## 1. In your agent's code: the SDK

The SDK packages are not on PyPI or npm yet. For now, install Python from
the repository or link the TypeScript package locally:

- **Python:** `pip install "hopframe @ git+https://github.com/jLuPSP/hopframe.git@main#subdirectory=sdk/python"`
- **TypeScript / JavaScript:** clone the repo, then follow [`sdk/typescript/README.md`](https://github.com/jLuPSP/hopframe/tree/main/sdk/typescript)

It hooks your agent's tool calls (LangChain, LangGraph, OpenAI Assistants,
Vercel AI SDK, or direct calls) and sends them to a Hopframe control plane.
It needs no traffic rerouting, but it still needs a control plane. It
**observes and advises** without hard-blocking.

## 2. Bolt onto a gateway you already run: ext_authz

If you already run Envoy (or Istio, Gloo, Emissary, Envoy AI Gateway),
Hopframe plugs in as an authorization check. For every inbound MCP message
the gateway asks Hopframe "allow or block?" Hopframe runs its request-side
detectors and returns a decision. It requires no agent changes. With a control
plane configured, its events join the same tamper-evident audit log. It sees
only messages going **to** the tool, never the tool's replies coming back.
(`cmd/mcp-extauthz`.)

## 3. Hopframe as your front door: the gateway

Hopframe itself stands in front of many MCP servers at one address, routes
each request to the right one, and inspects MCP traffic in **both** directions.
It shares quarantine and MCP-side taint state across those routes. Pair it with
an A2A sensor, using the same `agent_run_id`, for MCP-to-A2A lineage. You host
it. (`cmd/mcp-gateway`.)

## 4. In front of one tool: the inline sensor

Hopframe sits directly between an agent and a single MCP or A2A server. It
provides full power for that one wire in the simplest "drop it in front" shape.
(`cmd/mcp-sensor`, `cmd/a2a-sensor`, `cmd/mcp-stdio-sensor`.)

## 5. *(Coming)* Bolt onto your gateway, with reply inspection: ext_proc

This option works like option 2, except Hopframe also sees and can rewrite the
tool's replies. It reaches full power through your existing gateway. It is
planned and not built yet.

## At a glance

Legend: ✓ yes · ~ partial / advisory · ✗ no

| | SDK (Python / TS) | ext_authz | ext_proc *(planned)* | Gateway / inline sensor |
|---|:--:|:--:|:--:|:--:|
| No traffic rerouting | ✓ | ✗ | ✗ | ✗ |
| No agent code changes | ✗ | ✓ | ✓ | ✓ |
| Hard-blocks bad requests | ~ | ✓ | ✓ | ✓ |
| Inspects tool **replies** (poisoned descriptions, leaked results) | ~ | ✗ | ✓ | ✓ |
| Cross-protocol taint (MCP → A2A) | ~ | ✗ | ✓ | ~¹ |
| Tamper-evident audit log | ✓² | ✓² | ✓² | ✓² |

1. Requires both an MCP-observing and an A2A-observing surface with a shared run id. The combined sensor includes both.
2. Requires events to reach a configured control plane; a local NDJSON sink alone is not signed.

Because ext_authz never sees the reply, a poisoned tool *description* slips
past it. The gateway or sensor catches it. The `deploy/labs/extauthz-e2e/`
lab demonstrates this.

## How to pick

- **Visibility without rerouting, advisory only:** SDK.
- **An existing Envoy-style gateway, blocking, and no code changes:** ext_authz.
- **Full protection with hosting:** Gateway (many tools) or inline sensor (one
  tool).

The surfaces stack. Run the SDK *and* a gateway on the same agent run and you
get the agent's-eye view (which tool, which step) lined up with what crossed the
wire on one timeline.

## What no surface can see

Hopframe inspects the wire when one end of the traffic is on infrastructure you
own. Two cases have no third-party intercept today, Hopframe included:

- **Both endpoints managed by the same cloud vendor** (a Bedrock Agent calling a
  Bedrock-hosted tool, an OpenAI Assistant calling one of OpenAI's tools). The
traffic never leaves the vendor's plane.
- **Cross-vendor managed-to-managed** (a Bedrock Agent calling a third-party
SaaS MCP). The traffic egresses the platform without crossing your
infrastructure. The SaaS owner would have to run Hopframe in front of its own
MCP service.

Where those cells matter, pair Hopframe (protocol layer, customer side) with the
platform's first-party model-layer guard. The two cover different surfaces.

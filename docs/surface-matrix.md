# Where Hopframe runs

Hopframe is one detection engine that runs in several places. The engine
(rules, quarantine, cross-protocol taint, the signed audit log) stays the same.
Choose **where it sits** based on where your agents and tools live and how much
enforcement you need.

There are four ways to run it today, plus one on the way.

## 1. In your agent's code: the SDK

You import the package into your agent in its own language:

- **Python:** `pip install hopframe`
- **TypeScript / JavaScript:** `npm install @hopframe/sdk`

It hooks your agent's tool calls (LangChain, LangGraph, OpenAI Assistants,
Vercel AI SDK, or direct calls) and reports them to the Hopframe timeline.
This option requires no infrastructure and no traffic rerouting. It **observes
and advises** without hard-blocking. Use it when you cannot sit on the wire or
want visibility first.

## 2. Bolt onto a gateway you already run: ext_authz

If you already run Envoy (or Istio, Gloo, Emissary, Envoy AI Gateway),
Hopframe plugs in as an authorization check. For every inbound MCP message
the gateway asks Hopframe "allow or block?" and Hopframe answers after running
the full detection pipeline. It requires no changes to your agents and writes
the same audit log. It only sees messages going **to** the tool. It cannot see
the tool's replies coming back. (`cmd/mcp-extauthz`.)

## 3. Hopframe as your front door: the gateway

Hopframe itself stands in front of many MCP servers at one address, routes
each request to the right one, and inspects everything in **both**
directions. It shares state (quarantine, taint) across all your tools. You host
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
| No infrastructure to run | ✓ | ✗ | ✗ | ✗ |
| No agent code changes | ✗ | ✓ | ✓ | ✓ |
| Hard-blocks bad requests | ~ | ✓ | ✓ | ✓ |
| Inspects tool **replies** (poisoned descriptions, leaked results) | ~ | ✗ | ✓ | ✓ |
| Cross-protocol taint (MCP → A2A) | ~ | ✗ | ✓ | ✓ |
| Tamper-evident audit log | ✓ | ✓ | ✓ | ✓ |

**The SDK is the easiest and provides advisory results. ext_authz provides broad,
no-code request coverage. The gateway and inline sensor provide full power and
require hosting.** ext_authz never sees the reply, so a poisoned tool
*description* slips past it. The gateway or sensor catches it. The
`deploy/labs/extauthz-e2e/` lab demonstrates this.

## How to pick

- **Visibility and the fastest start:** SDK.
- **An existing Envoy-style gateway, blocking, and no code changes:** ext_authz.
- **Full protection with hosting:** Gateway (many tools) or inline sensor (one
  tool).

The surfaces stack. Run the SDK *and* a gateway on the same agent run and you
get the agent's-eye view (which tool, which step) lined up with what crossed the
wire on one timeline.

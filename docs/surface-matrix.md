# Where Hopframe runs

Hopframe is one detection engine you can run in several places. The engine
(rules, quarantine, cross-protocol taint, the signed audit log) is the same
everywhere. You just pick **where it sits**, based on where your agents and
tools live and how much enforcement you need.

There are four ways to run it today, plus one on the way.

## 1. In your agent's code — the SDK

A package you import into your agent, in your agent's own language:

- **Python:** `pip install hopframe`
- **TypeScript / JavaScript:** `npm install @hopframe/sdk`

It hooks your agent's tool calls (LangChain, LangGraph, OpenAI Assistants,
Vercel AI SDK, or direct calls) and reports them to the Hopframe timeline.
Lowest friction: no infrastructure to run, no traffic to re-point. The
trade-off is that it **observes and advises** rather than hard-blocking. Best
when you can't sit on the wire, or you just want visibility first.

## 2. Bolt onto a gateway you already run — ext_authz

If you already run Envoy (or Istio, Gloo, Emissary, Envoy AI Gateway),
Hopframe plugs in as an authorization check. For every inbound MCP message
the gateway asks Hopframe "allow or block?" and Hopframe answers after running
the full detection pipeline. No changes to your agents, and it writes the same
audit log. The limit: it only sees messages going **to** the tool, not the
tool's replies coming back. (`cmd/mcp-extauthz`.)

## 3. Hopframe as your front door — the gateway

Hopframe itself stands in front of many MCP servers at one address, routes
each request to the right one, and inspects everything in **both**
directions. Full power, and state (quarantine, taint) is shared across all
your tools. You host it. (`cmd/mcp-gateway`.)

## 4. In front of one tool — the inline sensor

Hopframe sits directly between an agent and a single MCP or A2A server. Full
power for that one wire, simplest "drop it in front" shape.
(`cmd/mcp-sensor`, `cmd/a2a-sensor`, `cmd/mcp-stdio-sensor`.)

## 5. *(Coming)* Bolt onto your gateway, with reply inspection — ext_proc

Like option 2, but Hopframe also sees and can rewrite the tool's replies, so
it reaches full power through your existing gateway. Planned; not built yet.

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

The pattern: **the SDK is easiest but advisory; ext_authz is broad and
no-code but request-only; the gateway and inline sensor are full-power but you
host them.** That single fact, that ext_authz never sees the reply, is why a
poisoned tool *description* slips past it but is caught by the gateway or
sensor. The `deploy/labs/extauthz-e2e/` lab demonstrates exactly this.

## How to pick

- **Just want visibility, fastest start?** SDK.
- **Already run an Envoy-style gateway and want to block bad requests with no
  code changes?** ext_authz.
- **Want the full protection and are happy to host it?** Gateway (many tools)
  or inline sensor (one tool).

The surfaces stack. Run the SDK *and* a gateway on the same agent run and you
get the agent's-eye view (which tool, which step) lined up with the on-the-wire
truth (what actually crossed), on one timeline.

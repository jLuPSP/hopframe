# Per-surface capability matrix

Hopframe is one detection brain with several data-plane surfaces. The brain
is `internal/pipeline.Pipeline` (the four-stage detection pipeline plus
quarantine, taint, task-state, and the audit emitter). Every surface is a
thin adapter that hands the pipeline a parsed protocol message and acts on
the verdict it returns. The pipeline does not own networking; the adapters
do. That is why the same detection and the same audit log are reachable from
a package import, an inline proxy, a multiplexing gateway, or someone else's
gateway.

What differs between surfaces is the **enforcement ceiling**, and it is not
marketing, it is mechanism. A surface can only carry a feature if it provides
what the feature needs. Three things decide it:

1. **Response visibility** — can the surface see the upstream's reply, not
   just the request?
2. **Body mutation** — can the surface rewrite a message in flight, not just
   allow or deny it?
3. **Cross-message state** — does the surface sit somewhere that accumulates
   per-agent-run state across many messages?

Sort any feature by those three axes and you know which surface carries it.

## The surfaces

| Surface | Mechanism | Owns data path? | Status |
| --- | --- | --- | --- |
| **Package SDK** (`hopframe-py`) | in-process framework callbacks emit events | no | shipping |
| **ext_authz attach** (`internal/extauthz`, `cmd/mcp-extauthz`) | Envoy HTTP external-authorization call-out: allow / deny | no (the gateway does) | shipping |
| **ext_proc attach** | Envoy external-processing gRPC stream: inspect + mutate both directions | no (the gateway does) | planned |
| **Native inline sensor** (`internal/proxy`, `cmd/mcp-sensor`) | reverse proxy on the wire | yes | shipping |
| **Native gateway** (`internal/gateway`, `cmd/mcp-gateway`) | inline proxy with a routes table over N upstreams | yes | shipping |

The native sensor and native gateway are the same surface at different
arities: the gateway is the sensor with a routes table, one proxy per route
sharing one pipeline, so its capability column is identical.

## The matrix

Legend: **✓** full · **◐** partial · **✗** not on this surface · **(p)** planned (ext_proc).

| Capability | Package SDK | ext_authz | ext_proc | Native sensor / gateway |
| --- | :---: | :---: | :---: | :---: |
| Inbound request detection (`tools/call` args) | ✓ | ✓ | ✓ (p) | ✓ |
| Four-stage pipeline (regex, heuristic, LLM judge) | ✓ | ✓ | ✓ (p) | ✓ |
| Hard block (deny a request) | ◐ soft | ✓ | ✓ (p) | ✓ |
| Response detection (`tools/list` descriptions, tool results) | ✓ | ✗ | ✓ (p) | ✓ |
| Quarantine **enforce** (block a `tools/call`) | ◐ | ✓ | ✓ (p) | ✓ |
| Quarantine **populate** (learn from `tools/list` response) | ✓ | ✗ | ✓ (p) | ✓ |
| Cross-protocol taint **tag** (on MCP results) | ✓ | ✗ | ✓ (p) | ✓ |
| Cross-protocol taint **check / block** (A2A leak) | ◐ | ◐ runs but empty | ✓ (p) | ✓ |
| SSE chunk inspect **and replace** | n/a | ✗ | ◐ (p) streaming is the hard part | ✓ |
| Synthesize a block body | ◐ | ◐ deny body only | ✓ (p) | ✓ |
| Agent-card validation + signature | ✗ | ✗ | ✓ (p) | ✓ |
| A2A task-state / counterparty drift | ◐ | ◐ request-side only | ✓ (p) | ✓ |
| Audit log emission (hash-chained, signed) | ✓ | ✓ | ✓ (p) | ✓ |
| `agent_run_id` correlation across the hop | ✓ | ✓ | ✓ (p) | ✓ |

### Why ext_authz drops the differentiators

ext_authz is request-side and decision-only: it sees a buffered request and
returns allow or deny. It never sees a response. The two stateful
differentiators each **learn on the response and act on the request**, so
ext_authz gets the act without the learn:

- **Quarantine** populates from the `tools/list` *response* and enforces by
  blocking a `tools/call` *request*. ext_authz can enforce an existing entry
  but can never see the response that would fill the set.
- **Cross-protocol taint** tags leaf strings in MCP tool-call *responses* and
  checks A2A *requests* for reuse. The check is request-side so it runs, but
  it has nothing to match because the tagging step happened on a response
  ext_authz never saw.

So ext_authz is the **breadth** surface: block known-bad inputs, emit the
audit log, correlate runs, attach to the whole Envoy ecosystem with no
per-gateway code. It is not the surface for taint or tool-poisoning
quarantine. Deploy it knowing that.

### Why ext_proc reaches near-parity

ext_proc sees and can mutate both directions and supports streaming, so it
provides response visibility, mutation, and (because it is a centralized
call-out) a natural home for cross-message state. It can carry essentially
the full feature set. The honest caveats are engineering, not capability:
streaming-body mutation (the SSE rewrite) is the fiddly part, every message
pays a network hop, and the stateful subsystems must live in the call-out
service with their own availability story.

### Why the native surfaces are the gold reference

The native sensor and gateway own the data path, run in-process at
microsecond latency, and have no response blind spot. Everything in the
matrix is ✓ by construction because the adapter is the proxy, not a call-out
into someone else's proxy.

## Choosing a surface

- **Lowest friction, no re-pointing, fail-safe** → Package SDK. Observe and
  soft-enforce inside the agent. The land-and-expand on-ramp.
- **Block + audit + correlate everywhere, instantly, riding your existing
  gateway** → ext_authz attach. Accept the request-side ceiling.
- **Full fidelity through your existing Envoy mesh** → ext_proc attach (when
  shipped). The bridge you build when topology leaves no other way in.
- **Full fidelity, you own the path, one address in front of many upstreams**
  → Native gateway. The depth surface.

The surfaces stack. Running the SDK and a native surface on the same
`agent_run_id` correlates in-process attribution (which tool, which callback)
with on-the-wire truth (what actually crossed), all on one forensic timeline.

# Hopframe and the adjacent tools

Hopframe lives at the protocol layer of agent traffic, inline on the MCP and A2A wire. Most adjacent tools live at the model layer (the input and output of an LLM call) or the routing layer (gateways). These tools cover different surfaces and work together.

This landscape map uses each tool's public docs, open-source code, and product pages as of mid-2026. I cross-checked it against the multi-source research in [landscape-research.md](landscape-research.md). I identify claims that rest only on vendor marketing and claims that I could not verify.

## The four layers

- **Model-boundary guardrails** inspect the prompt going into the LLM and the response coming back: Bedrock Guardrails, Model Armor, Lakera Guard, NeMo Guardrails. They never see MCP or A2A protocol content, because it is not a prompt.
- **MCP and agent gateways** route, authenticate, and rate-limit agent traffic, sometimes with policy. Some inspect MCP tool calls at admission.
- **Inline protocol-wire inspection** reads the live JSON-RPC and A2A traffic and acts on its content. This is Hopframe's primary layer. The one credible open peer here is Solo.io agentgateway.
- **Audit and provenance** records what happened in a verifiable form. Mostly conventional logs today; a few projects sign static artifacts.

Hopframe spans the last two: inline content detection plus a tamper-evident audit log.

## Common questions

### We already run Bedrock Guardrails, Model Armor, or Lakera Guard. Does this overlap?

The tools overlap only at the edges. Those model-boundary filters inspect the prompt and response inside the model call. None of them sit between an MCP server and the agent. A poisoned tool description can enter the model's context without them seeing it. Both tools can use layer-1 regex to catch classic prompt-injection strings in a tool result body. Hopframe catches the string on the tool's response wire before it becomes a prompt. The guardrail catches it inside the prompt after the agent builds it. Running both covers both layers.

### We use Bedrock Agents or OpenAI Assistants and cannot run a sidecar in the agent's runtime.

Hopframe deploys at the protocol counterparty you control. If the agent calls an MCP server you host, put the sensor in front of that server. Hopframe inspects the protocol traffic as it crosses your network, regardless of the agent's runtime. Nobody can intercept traffic when the same cloud vendor manages both endpoints and the traffic never crosses your network. Pair Hopframe with that vendor's first-party guard for that case.

### We already have a SIEM.

Hopframe sends findings upstream to it. The signed-webhook and Splunk HEC exporters ship findings into your existing analytics plane. SIEMs do not parse MCP or A2A semantics on their own. Hopframe provides them with protocol-level findings.

## The landscape, honestly

The closest peer is **[Solo.io agentgateway](https://www.solo.io/products/agentgateway)** (Apache 2.0, Linux Foundation). It sits inline on both MCP and A2A with no code changes. It inspects MCP tool calls beyond the prompt through tool-server fingerprinting, versioning, and runtime policy against tool poisoning, rug-pulls, and shadowing. Three things separate Hopframe from it:

- **Detection depth.** agentgateway's MCP inspection is gateway and policy oriented (auth, RBAC, fingerprinting, CEL rules). Hopframe runs a four-stage content pipeline with regex, a heuristic feature-density classifier, an optional LLM judge for the uncertain band, and behavioral anomaly detection. It applies NFKC normalization and base64 decoding before matching.
- **Where the guardrails run.** agentgateway's prompt-injection and data-leak guardrails operate on the client-to-LLM channel (the model boundary), not on MCP tool-description or tool-result content, and not on A2A envelopes.
- **Audit.** agentgateway advertises "cryptographically verifiable audit trails," but that claim did not hold up under verification. Hopframe ships a SHA-256 hash chain, Ed25519 per-record signatures, and optional Sigstore Rekor anchoring.

Others, briefly:

- **IBM ContextForge** (Apache 2.0, self-hosted) is a gateway that federates MCP, A2A, and REST/gRPC with governance and observability. Optional guardrail plugins provide security. Content detection is not enabled by default. It has no cryptographic audit today. A hash chain is on its roadmap, while signing and Rekor are not.
- **Invariant MCP-Scan** (now part of Snyk's agent-scan) is the closest peer on MCP tool poisoning. It is a static scanner of tool metadata (names, descriptions, schemas). It does not inspect tool results or A2A envelopes inline. Its detection runs against the Invariant Guardrails API by default, so traffic can leave your environment. It has no A2A coverage.
- **sigstore-a2a** keyless-signs static A2A Agent Cards via Sigstore. That is provenance for a configuration artifact, not inline inspection or a runtime audit log.
- **AIP** (academic) carries cross-protocol identity and delegation tokens across MCP, A2A, and HTTP. This rare cross-protocol solution binds *who authorized what*. It does not track *what data crossed* or provide taint detection.

**I did not find a peer for cross-protocol data taint** (an MCP result reused in an A2A task to an unallowlisted peer). I also found no peer for A2A task-state or counterparty drift, a unified MCP+A2A forensic timeline, or a detection-plus-cryptographic-audit combination running entirely in your environment. This finding is bounded by the tools I reviewed. Several 2025-2026 startups named in the space (Runlayer, Operant AI, Lasso, Cisco AI Defense, Zenity, Aim, Noma, Pillar, Prompt Security, HiddenLayer, Protect AI) did not surface verifiable primary-source claims in my research. I treated them as "not evaluated."

## Capability matrix

This rough map shows who covers what. Read it with the caveats above. Cells come from vendor docs, open-source code, and product pages. Several rest on marketing rather than tested mechanisms, and the fast-moving startups are necessarily incomplete. Corrections are welcome via PR.

Legend: **✓** in code or docs · **◐** partial (one layer, or via plugin or policy) · **☁** detection runs in the vendor's cloud · **–** not present or not advertised · **?** plausible but unverified here

| Surface | Hopframe | Solo.io agentgateway | IBM ContextForge | Invariant / Snyk agent-scan | model-boundary guards |
| --- | :---: | :---: | :---: | :---: | :---: |
| License / where detection runs | BSL→Apache; rules Apache today; in-env | Apache 2.0; in-env (Enterprise tier closed) | Apache 2.0; in-env | OSS proxy + Snyk SaaS tier | mixed; mostly cloud |
| Inline on the MCP wire | ✓ | ✓ | ◐ gateway | ✓ proxy mode | – |
| Inline on the A2A wire | ✓ | ✓ | ◐ gateway | – | – |
| Tool poisoning at `tools/list` | ✓ inline quarantine | ◐ fingerprint + policy | – | ✓ static + proxy | – |
| Four-stage content detection | ✓ | ◐ policy | ◐ via plugin | ◐ | ◐ prompt only |
| Cross-protocol taint (MCP→A2A) | ✓ | – | – | – | – |
| A2A task-state / counterparty drift | ✓ | – | – | – | – |
| NFKC + base64 normalization before matching | ✓ | ? | – | ? | ? |
| Cryptographic audit (hash chain + Ed25519 + Rekor) | ✓ | – (claim refuted) | – (roadmap: hash chain only) | – | – |
| MCP + A2A on one forensic timeline | ✓ | – | – | – | – |
| Detection rules open and inspectable in-tree | ✓ | ◐ | ◐ | ◐ | – |

## The threat model is now codified

As of mid-2026, standards describe the threat model:

- **OWASP Top 10 for Agentic Applications (2026).** ASI07 Insecure Inter-Agent Communication names A2A and MCP and covers spoofed, intercepted, and manipulated agent messages, protocol downgrade, and delegation-token replay.
- **OWASP MCP Top 10.** MCP03 Tool Poisoning (rug pulls, schema poisoning, tool shadowing) and MCP08 Lack of Audit and Telemetry, which recommends append-only or WORM logs with SHA-256 hashing for integrity. Hopframe's hash chain is a stronger version of that.
- **arXiv:2602.11327** (Canadian Institute for Cybersecurity and Mastercard). MCP has no protocol-level mechanism binding a tool's identity to its provider. Combining MCP, A2A, ANP, and Agora creates confusion, downgrade, and relay-abuse risk. The paper substantiates the cross-protocol motivation.

Sources and the full verification record are in [landscape-research.md](landscape-research.md).

## What you might run alongside it

| You also run | What Hopframe adds |
| --- | --- |
| **Model-layer filters** (Bedrock Guardrails, Model Armor, Lakera, NeMo) | Tool-description quarantine, cross-protocol taint, A2A drift, signed audit. None of these are visible at the model boundary. |
| **AI red-team scanners** (Garak and similar) | Runtime evidence of attacks that landed, with cryptographic proof. Red-team tools generate attacks; Hopframe records what got through. |
| **AI gateways** (Portkey, Kong AI Gateway, Cloudflare AI Gateway, Envoy AI Gateway) | Inline content detection on the routed traffic. Gateways route, auth, and rate-limit; Hopframe inspects content. |
| **Cloud-native agent platforms** (Bedrock AgentCore Policy, Azure Foundry Agents, Vertex Agent Engine) | The cloud-native guards do authorization, not content detection. Hopframe adds the protocol-layer detection they do not. |
| **OSS MCP tooling** (Solo.io agentgateway, Invariant / Snyk agent-scan, IBM ContextForge) | A2A coverage, cross-protocol taint, MCP+A2A correlation on one timeline, and an in-tree cryptographic audit log. These peers cover the MCP side; Hopframe extends to the second protocol and the audit layer. |
| **A SIEM** (Splunk, Datadog, Sentry) | Protocol semantics upstreamed via signed webhook or Splunk HEC. |

## What Hopframe is not

- A model-side safety filter. That is your model vendor's job.
- A gateway, an IAM, or a SIEM.
- A compliance auto-pilot. It makes evidence verifiable; the controls remain yours.
- An offline scanner. It is inline by design; at this layer, runtime evidence beats speculative scanning.

## Where the surfaces overlap, and how to think about it

The honest overlap with model-layer filters is layer-1 prompt-injection regex against the text of tool arguments and tool results. Both Lakera and Hopframe will catch "ignore previous instructions" in the body of a tool return. They catch it at different moments and with different metadata:

- A model-layer filter sees the suspicious string as part of the prompt, after the agent has built it. It can block the prompt. It does not know which tool produced the string.
- Hopframe sees the suspicious string on the tool's response wire, before it enters the prompt. It can quarantine the tool itself, mark the counterparty as risky, propagate taint into A2A, and stamp the rule's content hash onto the finding for reproducibility.

Running both gives you coverage at both layers and a chain-of-custody audit trail that the model-layer tools do not produce.

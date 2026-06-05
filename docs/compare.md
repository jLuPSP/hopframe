# Hopframe vs adjacent tools

Hopframe lives at the protocol layer of agent traffic. Most adjacent tools live at the model layer (input/output of an LLM call) or the routing layer (gateways). Different surfaces; they stack rather than substitute.

This page covers the questions that come up most often in evaluation calls.

## The three buyer questions

### Q: We already run Bedrock Guardrails, Model Armor, or Lakera Guard. Do we need this?

Different layer. Bedrock Guardrails and Model Armor are model-layer filters that inspect the prompt going to the LLM and the response coming back, inside the cloud vendor's plane. Lakera Guard is the same idea as a vendor-agnostic SaaS API. None of them sit between an MCP server and the agent, so a poisoned tool description goes into the model's context invisibly to them.

Hopframe inspects the protocol envelope crossing the wire. The two surfaces stack; they do not substitute. Layer-1 regex coverage on classic prompt injection does overlap, so the pure-overlap dollar is small. The protocol-layer surface (tool poisoning at `tools/list`, cross-protocol taint, A2A drift, signed audit) is where Hopframe earns its keep.

### Q: We use AWS Bedrock Agents and we cannot run a sidecar in the agent's runtime.

Hopframe deploys at the protocol counterparty you control, not at the agent. If the Bedrock Agent calls an MCP server you host, deploy `mcp-sensor` in front of the MCP server. The agent's runtime is irrelevant; the protocol traffic crosses your VPC and Hopframe inspects it there.

The same shape works for OpenAI Assistants, Azure AI Foundry Agents, and Vertex AI Agent Engine. Full matrix in [deployment-shapes.md](deployment-shapes.md).

The cell where no third party can intercept is the one where both endpoints are managed by the same cloud vendor and never cross your network. Pair Hopframe (protocol layer) with that vendor's first-party model-layer guard for that cell.

### Q: We have a SIEM (Splunk, Datadog, Sentry). Why another tool?

Hopframe upstreams to your SIEM. The HMAC-signed webhook and Splunk HEC exporters ship every finding into your existing analytics plane. SIEMs do not parse MCP or A2A semantics on their own; Hopframe is the upstream that puts protocol-level findings in front of them.

## Capability matrix

The agent-security space went from "early" to "crowded with money" in 2025-2026. ~$3.6B disclosed funding in the last year, ~$392M announced in one week around RSAC March 2026. But most of that hasn't shipped yet, and most of what has shipped covers different surfaces than Hopframe. Here is the honest map, based on each vendor's public docs / open-source code / product pages as of April 2026.

Legend: **✓** published in code or docs &middot; **◐** partial (one layer, or via plugin) &middot; **☁** hosted-only (detection logic runs in the vendor's cloud, OSS layer is a shim) &middot; **–** not present or not advertised

| Detection / audit surface | Hopframe | Runlayer<sup>1</sup> | Operant AI<sup>2</sup> | Lasso<sup>3</sup> | Solo.io agentgateway<sup>4</sup> | Cisco DefenseClaw<sup>5</sup> | IBM ContextForge<sup>6</sup> | Invariant / Snyk agent-scan<sup>7</sup> | ArkForge<sup>8</sup> |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **License + where detection runs** | BSL 1.1 → Apache 2.0; rules Apache 2.0 today; in-env | Closed SaaS, paid | Closed SaaS, paid | OSS shim + paid SaaS classifier | Apache 2.0; in-env | Apache 2.0; admission-time scan | Apache 2.0; in-env | OSS proxy + Snyk Evo SaaS | Closed SaaS, paid |
| Tool poisoning at `tools/list` (inline quarantine + short-circuit on subsequent `tools/call`) | ✓ | ◐ | ◐ | ☁ | – | ◐<sub>scan</sub> | – | ✓<sub>proxy</sub> | – |
| Credential-exfil regex pack on tool-call responses (AWS, GitHub, Slack, OpenAI, Anthropic, PEM, GCP, Azure) | ✓ | ☁ | ☁ | ◐ | ◐ | ◐ | ◐ | ◐<sub>via Presidio</sub> | – |
| Four-layer prompt-injection pipeline (regex → heuristic classifier → optional LLM judge → behavioral) | ✓ | ☁ | ☁ | ☁ | ◐<sub>via plugin</sub> | ◐ | ◐ | ◐<sub>indirect-PI rule, proxy</sub> | – |
| Cross-protocol taint (MCP result fingerprinted, blocked on reuse in A2A task to unallowlisted peer) | ✓ | – | – | – | – | – | – | – | – |
| A2A task drift (illegal state transitions, mid-task counterparty change, task-id reuse) | ✓ | – | – | – | – | ◐<sub>scan</sub> | – | – | – |
| Per-counterparty risk scoring with severity weighting and time decay | ✓ | – | – | – | – | – | – | – | – |
| NFKC normalization + base64 unwrapping before matching (defeats invisible-Unicode + base64 bypasses) | ✓ | – | – | – | – | – | – | – | – |
| Cryptographic audit (SHA-256 hash chain + Ed25519 per-record signatures + Merkle proofs + optional Sigstore Rekor anchoring) | ✓ | – | – | – | – | – | – | – | ☁<sub>SaaS, audit-only, MCP-only</sub> |
| MCP + A2A correlation on a single `agent_run_id` forensic timeline | ✓ | – | – | – | – | – | – | – | – |
| Detection rules open and inspectable (`content/*.yaml` in tree); no SaaS callout for detection | ✓ | – | – | – | ◐ | ✓ | ✓ | ◐ | – |

**Three surfaces with no published peer in this set:** cross-protocol taint (MCP→A2A), A2A task drift, and MCP+A2A correlation on a single timeline. Cryptographic audit has a SaaS-only peer (ArkForge), but no peer that pairs detection with audit and runs both in your environment. Per-counterparty risk scoring and NFKC/base64 normalization are not advertised by any peer reviewed here. Tool poisoning at `tools/list` has one peer with full inline coverage (Invariant Labs' mcp-scan in proxy mode, now part of Snyk's agent-scan); the four-layer pipeline has only partial peers because the heuristic + behavioral layers are unique.

**Open + free is itself a feature.** The first row of the matrix is the one buyers in regulated environments often care about most. Hopframe ships under BSL 1.1 with the rule pack and benchmark corpus Apache 2.0 today; you can self-host the entire stack at zero per-call cost, read every detector, and the BSL Change Date converts the rest to Apache 2.0 three years after each release. Of the eight peers above: three are closed SaaS (Runlayer, Operant AI, ArkForge), one is OSS-shim-with-paid-classifier (Lasso), one is hybrid OSS-with-paid-reporting (Snyk agent-scan), and three are fully OSS but ship less detection in-tree (Solo.io agentgateway, Cisco DefenseClaw, IBM ContextForge).

**The "OSS gateway" footnote.** Lasso's [`mcp-gateway`](https://github.com/lasso-security/mcp-gateway) is open-source, but its detection plugin POSTs every request and response to `https://server.lasso.security/gateway/v3/classify` for classification. The OSS layer alone ships only token-regex masking and PII via Presidio. If your data-residency posture forbids your tool-call traffic leaving your environment for vendor classification, the open-source label is misleading. **Hopframe runs every detector in your environment**; every rule is a YAML file in [`content/`](../content/), every signature is your own.

**The "OSS scanner" footnote.** Invariant Labs' [`mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan) was the closest open-source peer on the MCP side until Snyk acquired/integrated Invariant in late 2025; the current line is [`github.com/snyk/agent-scan`](https://github.com/snyk/agent-scan). The static-scan and proxy modes remain open and run locally; Snyk's Evo enterprise tier adds a hosted reporting plane. Hopframe stays fully local with no Evo-tier callout. Honest trade-off: mcp-scan has more detection-corpus mileage; Hopframe is alpha and explicit about it, but covers A2A and cross-protocol surfaces mcp-scan does not.

<sub>1. Runlayer is closed-source SaaS; capability assessment is from product page + announcement coverage. 2. Operant AI: Agent Protector + CodeInjectionGuard + MCP Gateway product pages, Feb-Apr 2026. 3. Lasso: github.com/lasso-security/mcp-gateway code + OSS plugin set. 4. Solo.io agentgateway: github.com/agentgateway/agentgateway code + Solo.io product docs. 5. Cisco DefenseClaw: github.com/cisco-ai-defense/defenseclaw code, open-sourced RSAC March 2026. "scan" indicates admission-time/pre-deployment, not inline. 6. IBM ContextForge: github.com/IBM/mcp-context-forge plugin set as of April 2026. 7. Invariant Labs mcp-scan, now github.com/snyk/agent-scan after Snyk's late-2025 acquisition. "proxy" indicates the runtime proxy mode that ships PII detection, indirect prompt injection, tool pinning, and custom guardrails in-environment; Snyk Evo enterprise mode adds a hosted reporting tier. 8. ArkForge: certifying-proxy SaaS issuing Ed25519 + RFC 3161 + Sigstore Rekor receipts; audit-only, no detection layer; pricing starts free at low volume, paid tiers above. Capability claims may have changed since this writing; check vendor docs. PRs welcome with corrections.</sub>

## What you also run with Hopframe

| You also run | Hopframe adds |
| --- | --- |
| **Bedrock Guardrails / Model Armor / Lakera Guard / NeMo Guardrails** (model-layer filtering) | Tool description quarantine, cross-protocol taint, A2A task drift, signed audit. None of these are visible at the model boundary. |
| **AI red-team scanners** (Garak, Tencent BlueLM-RAS) | Runtime evidence of attacks that landed, with cryptographic proof. Red-team tools generate attacks; Hopframe records what got through. |
| **AI gateways** (Portkey, Kong AI Gateway, Cloudflare AI Gateway, Apollo MCP, Envoy AI Gateway) | Inline detection on the gateway-routed traffic. Quarantine. Cross-protocol taint. Signed audit. Gateways route + auth + rate-limit; Hopframe inspects content. |
| **Cloud-native agent platforms** (AWS Bedrock AgentCore Policy, Azure Foundry Agents, Vertex AI Agent Engine) | The cloud-native guards do authorization, not content detection. Hopframe adds detection of the protocol-layer attacks AgentCore Policy explicitly does not catch. |
| **Closed enterprise security** (Runlayer, Operant AI, HiddenLayer, PointGuard) | OSS detection content the operator can read and contribute to. Signed-by-default audit trail. No vendor lock-in on rule set. No SaaS callout for classification. |
| **OSS MCP scanners** (Invariant / Snyk agent-scan, Cisco DefenseClaw, IBM ContextForge) | A2A coverage, cross-protocol taint, MCP+A2A correlation on a single timeline, in-tree cryptographic audit. The OSS peers cover the MCP side; Hopframe extends to the second protocol. |
| **Cryptographic audit SaaS** (ArkForge) | Same Ed25519 + Sigstore Rekor receipt format, but inline detection at the same layer and self-hosted with no per-call cost. Audit alone tells you what happened; Hopframe also blocks. |
| **SIEM** (Splunk, Datadog, Sentry) | Upstream protocol semantics. Hopframe ships findings via HMAC-signed webhook or Splunk HEC. |
| **Nothing yet** | Start here. F1=1.0 on the 84-sample seed corpus, no SaaS dependency, no per-call cost. |

## What Hopframe is not

- A model-side safety filter (your model vendor's job).
- A gateway, IAM, or SIEM.
- A compliance auto-pilot (we make evidence verifiable; controls remain yours).
- An offline scanner (we are inline by design; runtime evidence beats speculative scanning at this layer).

## Where the surfaces overlap and how to think about it

The honest overlap with model-layer filters is on Layer-1 prompt-injection regex against the textual content of tool arguments and tool results. Both Lakera and Hopframe will catch "ignore previous instructions" in the body of a tool return. They catch it at different moments and with different metadata:

- A model-layer filter sees the suspicious string as part of the prompt, after the agent has built it. It can block the prompt. It does not know which tool produced the string.
- Hopframe sees the suspicious string on the tool's response wire, before it enters the prompt. It can quarantine the tool itself, mark the counterparty as risky, propagate taint into A2A, and stamp the rule's content hash onto the finding for reproducibility.

A buyer choosing between the two is asking the wrong question. A buyer running both gets coverage at both layers and a chain-of-custody audit trail no closed vendor includes by default.

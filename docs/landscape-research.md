# Agent-security landscape research (mid-2026)

This cited research supports the Hopframe case study. It is calibrated and non-promotional.
A multi-agent deep-research pass generated it (5 angles, 23 sources fetched, 113 claims
extracted, 25 adversarially verified with 3-vote refutation, 19 confirmed / 6 killed).

## Bottom line

As of mid-2026 the AI agent-security landscape splits into four layers:

- **(a) model-boundary guardrails** on the LLM prompt/response channel
- **(b) MCP / agent gateways** doing admission + inline routing with policy
- **(c) protocol-wire inline content inspection** of MCP/A2A traffic
- **(d) audit / provenance / forensics**

Hopframe's defensible position is the **combination of (c) + (d)**. It provides deep four-stage
in-environment detection on the live MCP *and* A2A wire plus a tamper-evident audit log
(SHA-256 hash chain + Ed25519 signatures + Sigstore Rekor anchoring). No single surveyed
tool provided all of these features: inline MCP+A2A wire detection in-environment, cross-protocol
data taint, A2A task-state/counterparty drift, unified MCP+A2A forensic timeline, and a
hash-chained + signed + Rekor-anchored audit log. (This is an absence-of-evidence finding,
with medium confidence, bounded by the tools surveyed.)

## The honest recalibration (read this before writing claims)

Solo.io's **agentgateway** sits inline on the MCP/A2A wire. It is a credible open-source project
(Apache 2.0, Rust, Linux Foundation), drops in with no code changes (Ambient waypoint),
proxies BOTH MCP and A2A, and inspects MCP tool calls beyond prompts
(tool-server fingerprinting, versioning, runtime policy against poisoning, rug-pulls, tool
shadowing). It is the closest peer, and the case study must name it.

**The remaining distinctions from agentgateway:**
- Its detection is gateway/policy-grade (auth, RBAC, fingerprinting, CEL policy). Hopframe uses
  four-stage content detection (regex -> heuristic density -> LLM judge -> behavioral, with
  NFKC/base64 normalization).
- Its LLM guardrails (prompt-injection/data-leak) are limited to the client<->LLM prompt/response
  channel. They do not run on MCP tool-description/result or A2A protocol content.
- Its claim to "cryptographically verifiable end-to-end audit trails" was adversarially
  **refuted (0-3)**. It is not an audit-layer peer.

## Per-tool placement (verified)

| Tool | Layer | Touches MCP/A2A protocol content? | Open / SaaS | Tamper-evident audit? |
|---|---|---|---|---|
| **Solo.io agentgateway** | (b)/(c) inline | Yes (MCP tool calls; gateway-grade). LLM guardrails are model-boundary only | Apache 2.0, in-env (Enterprise tier closed) | No (claim refuted) |
| **IBM ContextForge** | (b) gateway | Federates MCP/A2A; security via OPTIONAL guardrail plugins | Apache 2.0, self-hosted | No (hash chain on roadmap, Issue #535; no sign/Rekor) |
| **Invariant MCP-Scan** | static scan | MCP tool descriptions/names only; excludes results and A2A | Open, but traffic can leave env (Guardrails API default) | No |
| **sigstore-a2a** | (d) provenance | Signs STATIC A2A Agent Cards only; no inline inspection | Open (Sigstore) | Rekor for card signing, not runtime traffic |
| **AIP (arXiv:2603.24775)** | identity | Cross-protocol IDENTITY/delegation tokens (MCP/A2A/HTTP); not data taint | Academic | n/a (identity, not audit) |
| **IETF draft-sharif-agent-audit-trail** | (d) audit schema | Logs that actions occurred (action/input_hash/output_hash); not wire content | Draft | Logs hashes; its own hash-chain+ECDSA claim refuted |
| Model-boundary (Bedrock Guardrails, Model Armor, Lakera, NeMo) | (a) | No: prompt/response channel only | mixed | No |

**Unassessed this round (named in brief, no verified primary-source claims surfaced):**
Runlayer, Operant AI (launched an MCP gateway, surfaced but unverified), Lasso, Cisco AI
Defense (has an open-source A2A scanner), Zenity, Aim, Noma, Pillar, Prompt Security,
HiddenLayer, Protect AI. Treat them as "not evaluated."

## The three strongest, still-uncontested differentiators

No surveyed tool claimed any of these:
1. **Cross-protocol data taint:** sensitive data from an MCP tool result forwarded into an A2A
   task. (AIP does cross-protocol *identity*, not *data*.)
2. **A2A task-state / counterparty drift** mid-task. (OWASP ASI07 names the threat category but
   no tool ships the capability.)
3. **Unified MCP + A2A forensic timeline** correlating both protocols.

No surveyed tool ships the full **hash-chain + Ed25519 + Rekor** audit log
(ContextForge has hash-chain on roadmap only; IETF draft logs action hashes, not wire content).

## Standards now validate the thesis (the thought-leadership gold)

- **OWASP Top 10 for Agentic Applications 2026** (published Dec 9 2025, 100+ experts): **ASI07
  Insecure Inter-Agent Communication** explicitly names A2A and MCP and covers spoofed /
  intercepted / manipulated agent messages, protocol downgrade, delegation-token replay.
- **OWASP MCP Top 10:** **MCP03 Tool Poisoning** (rug pulls, schema poisoning, tool shadowing)
  and **MCP08 Lack of Audit and Telemetry**, which recommends append-only/WORM logs with
  **SHA-256 hashing** for integrity. Hopframe's hash chain is a stronger implementation of the
  same OWASP-recommended goal. (Beta/living-document status.)
- **arXiv:2602.11327** (Apr 2026, Canadian Institute for Cybersecurity + Mastercard): MCP has
  no protocol-level mechanism binding a tool's identity to its provider (wrong-provider
  execution measured up to 1.0); combining MCP/A2A/ANP/Agora creates confusion/downgrade/
  relay-abuse risk and calls for cross-protocol standards. It substantiates the cross-protocol motivation.
- **arXiv:2603.24775** (AIP) is the rare cross-protocol identity work. It confirms most solutions
  "address at most one transport."

## Caveats (carry these into the writing)

- Central differentiation finding is partly absence-of-evidence (medium confidence), bounded by
  the tools surveyed. Do NOT say "no one does X" flatly. Say "no tool I found, as of mid-2026."
- Vendor-capability findings rest on primary vendor/marketing sources (Solo, Invariant); they
  establish what tools ADVERTISE, not independently-tested efficacy.
- Time-sensitive: MCP 2026-07-28 RC adds OAuth 2.1/mTLS (connection auth, not tool-provider
  binding); ContextForge hash-chain roadmap; IETF drafts evolving. The hash-chain differentiator
  specifically may narrow; signed + Rekor + cross-protocol correlation differentiators are more durable.
- Hopframe's OWN capabilities (taint, drift, timeline, four-stage efficacy) were not independently
  tested here; the research verified the ABSENCE of peers, not Hopframe's implementation quality.

## Key sources

- Solo.io agentgateway: https://www.solo.io/products/agentgateway · https://www.solo.io/blog/introducing-solo-enterprise-for-agentgateway
- IBM ContextForge: https://github.com/IBM/mcp-context-forge
- Invariant MCP-Scan: https://invariantlabs.ai/blog/introducing-mcp-scan
- sigstore-a2a: https://github.com/sigstore/sigstore-a2a
- OWASP Agentic Top 10 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- arXiv:2602.11327 (tool-provider misbinding) · arXiv:2603.24775 (AIP)
- IETF agent audit trail: https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/
- Cisco open-source A2A scanner: https://blogs.cisco.com/ai/securing-ai-agents-with-ciscos-open-source-a2a-scanner

# Deployment shapes

Hopframe is inline by design. It inspects the JSON-RPC wire between an agent and its MCP/A2A counterparty. It does not inspect the model's prompts and responses. A single architectural rule covers every cell of the matrix below:

> **Hopframe deploys at the protocol counterparty you control.**

The agent runtime can be self-hosted, Vertex AI Agent Engine, AWS Bedrock Agents, OpenAI Assistants, Azure AI Foundry, Claude Desktop, Cursor, or `claude-code`. Hopframe can inspect messages crossing the wire when one end of the protocol traffic is on infrastructure you own.

This page maps realistic agent-runtime / counterparty combinations to the supported deployment shape. It also identifies the cells where no third-party security tool, including Hopframe, can intercept traffic.

## The deployment matrix

| Agent runtime | MCP/A2A counterparty | Deploy as | Coverage |
| --- | --- | --- | --- |
| Self-hosted (k8s, VM, Cloud Run with sidecar, Fargate) | Self-hosted | `mcp-sensor` / `a2a-sensor` sidecar in front of either endpoint | Full inline |
| Self-hosted | Third-party SaaS (e.g. GitHub MCP, Notion MCP) | `mcp-sensor` at the agent's egress | Full inline |
| Vertex AI Agent Engine | Self-hosted | `mcp-sensor` in your VPC, Agent Engine points at it. See [agent-engine.md](agent-engine.md) | Full inline |
| Vertex AI Agent Engine | Third-party SaaS | Hopframe Python SDK in the agent code, sensor for any self-hosted tool group | Full agent-side |
| AWS Bedrock Agents (Action Groups) | Self-hosted | `mcp-sensor` in front of the MCP server. Optionally Hopframe Python SDK inside the Action Group Lambda for tool-call attribution | Full MCP server side, tool-call surface inside Bedrock |
| AWS Bedrock Agents (direct MCP) | Self-hosted | `mcp-sensor` in front of the MCP server. Bedrock cannot have a sidecar, but the MCP server can | MCP server surface |
| AWS Bedrock Agents | Third-party SaaS only | Not directly interceptable. Pair with Bedrock Guardrails for model-layer filtering | None on the protocol layer |
| OpenAI Assistants / Agents | Self-hosted | Hopframe Python SDK at the tool dispatch boundary, sensor in front of self-hosted MCP servers | Full tool-call surface |
| Azure AI Foundry Agents | Self-hosted | Hopframe SDK at the function-dispatch boundary, sensor in front of self-hosted MCP servers | Full tool-call surface |
| Claude Desktop, Cursor, `claude-code` | Self-hosted MCP (stdio or HTTP) | `mcp-stdio-sensor` wraps the MCP server in the client config, or `mcp-sensor` in front of an HTTP MCP server | Full inline |
| Custom Python agent (LangChain, LangGraph, CrewAI) | Anywhere | Python SDK callbacks plus sensor on whichever endpoint you own | Full inline on owned endpoints, agent-side coverage everywhere else |

## The architectural principle, restated

Closed first-party tools (Bedrock Guardrails, Model Armor, Lakera) cover managed-runtime cells where a vendor integration exposes the prompt and response inside the platform's plane. They cannot see protocol traffic crossing customer infrastructure from a different plane.

Hopframe's coverage is the inverse. It cannot see the model's reasoning loop inside Bedrock. It sees every MCP tool description, tool result, and A2A task envelope that crosses an endpoint on your network. That endpoint visibility covers protocol-layer threats (tool poisoning, cross-protocol taint, A2A drift, counterparty change).

## What is not covered

Two cells have no third-party answer today:

1. **Both endpoints managed by the same cloud vendor.** This includes a Bedrock Agent calling a Bedrock-hosted tool or an OpenAI Assistant calling an OpenAI-hosted tool. The traffic never leaves the vendor's plane, so no third party intercepts it. Bedrock Guardrails or Model Armor handle this through first-party integration. Hopframe relies on the customer pulling at least one endpoint into infrastructure they control.

2. **Cross-vendor managed-to-managed.** This includes a Bedrock Agent calling a third-party SaaS MCP. The traffic egresses Bedrock to the SaaS without crossing customer infrastructure. The customer can request that the SaaS counterparty deploy Hopframe in front of its MCP service. The counterparty makes that decision.

Where these cells matter to a buyer, pair Hopframe (protocol layer, customer-side) with the platform's first-party model-layer guard (Bedrock Guardrails, Model Armor). The two tools cover different surfaces and work together.

## Choosing a shape

Three criteria resolve the choice:

1. **Agent runtime.** The agent runs on customer infrastructure, a hosted-but-customer-controlled platform (Vertex AI Agent Engine, Cloud Run), or a fully managed runtime (Bedrock Agents, OpenAI Assistants).
2. **MCP / A2A counterparty runtime.** The counterparties run on customer infrastructure, third-party SaaS, or the same vendor as the agent.
3. **Deployment goal.** The goal is full inline blocking or agent-side observability with selective enforcement.

The matrix above answers (1) and (2) together. (3) determines whether you use an in-process SDK callback or an inline sensor. The callback provides observability and soft enforcement at the dispatch seam. The sensor provides hard inline blocking with a 4-layer detection pipeline before the message crosses the wire.

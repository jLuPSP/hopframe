# Deployment shapes

Hopframe is inline by design. The thing it inspects is the JSON-RPC wire between an agent and its MCP/A2A counterparty, not the model's prompts and responses. That means a single architectural rule covers every cell of the matrix below:

> **Hopframe deploys at the protocol counterparty you control, not at the agent.**

The agent runtime can be self-hosted, Vertex AI Agent Engine, AWS Bedrock Agents, OpenAI Assistants, Azure AI Foundry, Claude Desktop, Cursor, or `claude-code`. As long as one end of the protocol traffic is on infrastructure you own, Hopframe can sit there and inspect the messages crossing the wire.

This page maps the realistic agent-runtime / counterparty combinations to the supported deployment shape. It also calls out the cells where no third-party security tool can intercept, including Hopframe.

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

Closed first-party tools (Bedrock Guardrails, Model Armor, Lakera) win on managed-runtime cells where they have a vendor integration that exposes the prompt and response inside the platform's plane. They lose on every cell where one endpoint is on customer infrastructure, because the protocol traffic crossing that infrastructure is invisible to a vendor that lives in a different plane.

Hopframe's coverage is the inverse. It cannot see the model's reasoning loop inside Bedrock. It does see every MCP tool description, tool result, and A2A task envelope that crosses an endpoint on your network. For protocol-layer threats (tool poisoning, cross-protocol taint, A2A drift, counterparty change), that endpoint visibility is what matters.

## What is not covered

Two cells have no third-party answer today:

1. **Both endpoints managed by the same cloud vendor.** A Bedrock Agent calling a Bedrock-hosted tool. An OpenAI Assistant calling an OpenAI-hosted tool. The traffic never leaves the vendor's plane. No third party intercepts. Bedrock Guardrails or Model Armor handle this through first-party integration; Hopframe relies on the customer pulling at least one endpoint into infrastructure they control.

2. **Cross-vendor managed-to-managed.** A Bedrock Agent calling a third-party SaaS MCP. The traffic egresses Bedrock to the SaaS without crossing customer infrastructure. The customer can request that the SaaS counterparty deploy Hopframe in front of their MCP service, but that is a counterparty decision, not a customer decision.

Where these cells matter to a buyer, the right honest answer is: pair Hopframe (protocol layer, customer-side) with the platform's first-party model-layer guard (Bedrock Guardrails, Model Armor). The two surfaces are different and they stack.

## Choosing a shape

Three questions resolve the choice:

1. **Where does the agent run?** Customer infrastructure, hosted-but-customer-controlled (Vertex AI Agent Engine, Cloud Run), or fully managed runtime (Bedrock Agents, OpenAI Assistants)?
2. **Where do the MCP / A2A counterparties run?** Customer infrastructure, third-party SaaS, or same vendor as the agent?
3. **Is the goal full inline blocking, or agent-side observability with selective enforcement?**

The matrix above answers (1) and (2) together. (3) determines whether you reach for an in-process SDK callback (observability, soft enforcement at the dispatch seam) or an inline sensor (hard inline blocking with a 4-layer detection pipeline before the message crosses the wire).

---
hide:
  - navigation
  - toc
---

<style>
.md-content__inner h1:first-of-type { display: none; }
.hopframe-hero {
  display: flex; flex-direction: column; align-items: center; text-align: center;
  padding: 2rem 1rem 1rem; gap: 1rem;
}
.hopframe-hero img { max-width: 720px; width: 100%; height: auto; }
.hopframe-hero p { max-width: 56ch; margin: 0; }
.hopframe-cta-row { display: flex; flex-wrap: wrap; gap: 0.6rem; justify-content: center; margin-top: 0.4rem; }
.hopframe-cta-row .md-button { margin: 0; }
.hopframe-grid {
  display: grid; gap: 1rem; margin: 2rem 0 1rem;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
}
.hopframe-card {
  border: 1px solid var(--md-default-fg-color--lightest);
  border-radius: 0.4rem; padding: 1rem 1.1rem; background: var(--md-default-bg-color);
  transition: border-color 120ms ease, transform 120ms ease;
}
.hopframe-card:hover { border-color: var(--md-accent-fg-color); }
.hopframe-card h3 { margin: 0 0 0.3rem; font-size: 1rem; }
.hopframe-card p { margin: 0 0 0.6rem; color: var(--md-default-fg-color--light); font-size: 0.85rem; }
.hopframe-card a.more { font-size: 0.85rem; }
</style>

<div class="hopframe-hero" markdown>

![Hopframe](https://raw.githubusercontent.com/jLuPSP/hopframe/main/docs/screenshots/hopframe-banner.svg){ loading=lazy }

**Source-available security mesh for agent traffic.** Sits inline between an agent and its MCP/A2A counterparties, catches attacks the model never sees, writes a hash-chained, signed audit chain a regulator can verify offline.

<div class="hopframe-cta-row" markdown>

[Quickstart](quickstart.md){ .md-button .md-button--primary }
[GitHub](https://github.com/jLuPSP/hopframe){ .md-button }
[v0.1.0 release](https://github.com/jLuPSP/hopframe/releases/tag/v0.1.0){ .md-button }

</div>

</div>

## Three commands to running

=== "With Go"

    ```bash
    git clone https://github.com/jLuPSP/hopframe.git
    cd hopframe
    make demo                                       # see the cinematic story
    make run UPSTREAM=http://your-mcp-server:8080   # use it in front of your MCP
    ```

    Requires Go 1.25+. Point your agent at `http://127.0.0.1:7080/mcp` instead of your MCP's URL. Hopframe inspects every JSON-RPC message in between.

=== "With Docker"

    ```bash
    git clone https://github.com/jLuPSP/hopframe.git
    cd hopframe
    UPSTREAM=http://your-mcp-server:8080 docker compose up
    ```

    No Go install needed. Multi-stage Dockerfile compiles inside the build. Same agent reroute as above.

=== "On Kubernetes"

    ```bash
    helm upgrade --install hopframe ./deploy/helm/hopframe \
      --namespace hopframe --create-namespace \
      --set mcpSensor.upstream.url=http://your-mcp-server:8080
    ```

    Uses the published `ghcr.io/jlupsp/hopframe:0.1.0` multi-arch image. Production-shape; see [Operations](operations.md) for the full chart values.

Open [http://127.0.0.1:7090](http://127.0.0.1:7090) for the operator UI.

## What changes when you deploy this

<div class="hopframe-grid" markdown>

<div class="hopframe-card" markdown>
### Tool poisoning blocked at the wire
Every `tools/list` response is inspected before the agent's model reads the tool descriptions. Instruction-override patterns, invisible-Unicode smuggling, and confused-deputy framings get the offending tool quarantined; subsequent `tools/call` to that tool short-circuits.
</div>

<div class="hopframe-card" markdown>
### Cross-protocol leaks caught
An MCP tool returns sensitive data; the agent forwards it in an A2A task to an unallowlisted peer. Hopframe blocks the leak. No model-layer filter sees this; it spans two protocol hops. **No published competitor ships this.**
</div>

<div class="hopframe-card" markdown>
### Every event is evidence
SHA-256 hash chain, optional Ed25519 per-record signatures, optional Sigstore Rekor anchoring. Hand a six-month report to an auditor and they re-walk the chain offline. Selective disclosure: one record can go to an auditor without revealing the rest.
</div>

<div class="hopframe-card" markdown>
### Editable policies, hot-reloaded
"Block tool poisoning on the github MCP for tenant acme; warn on prompt injection elsewhere." Author in the UI or `POST /v1/policies`, dry-run against the last 1000 events, sensors apply on the next heartbeat with no restart.
</div>

<div class="hopframe-card" markdown>
### Multi-tenant from day one
Tokens are scope-bound to a tenant; reads filter, writes pin `event.tenant_id`. Same binary serves a homelab and a regulated tenant.
</div>

<div class="hopframe-card" markdown>
### Two backing stores
File-backed NDJSON by default (zero dependencies). Postgres optional, compatible with Cloud SQL, AWS RDS, Azure Database for PostgreSQL, Aiven, Neon, Supabase, or self-hosted. Hash-chain semantics are byte-identical across both.
</div>

</div>

## Pick your path

<div class="hopframe-grid" markdown>

<div class="hopframe-card" markdown>
### I want to use it
[**Quickstart**](quickstart.md) for the 5-minute path. [**Install**](install.md) for production deployments. [**Operations**](operations.md) for backup, healthz, capacity.
</div>

<div class="hopframe-card" markdown>
### I want to understand it
[**What it catches**](capabilities.md) for the concrete attack list. [**Architecture**](architecture.md) for how the pieces fit. [**Threat model**](threat-model.md) for what's in and out of scope.
</div>

<div class="hopframe-card" markdown>
### I'm comparing tools
[**Compared to**](compare.md): capability matrix vs Bedrock Guardrails, Lakera, Model Armor, Runlayer, Operant, Lasso, Solo.io, Cisco, IBM. With citations.
</div>

<div class="hopframe-card" markdown>
### I want to drive it from code
[**CLI**](cli.md) for shell-driven workflows. [**HTTP API**](api.md) for direct integration. SDKs in Python and TypeScript at [`sdk/python`](https://github.com/jLuPSP/hopframe/tree/main/sdk/python) and [`sdk/typescript`](https://github.com/jLuPSP/hopframe/tree/main/sdk/typescript).
</div>

<div class="hopframe-card" markdown>
### I want to deploy at a managed agent runtime
[**Deployment shapes**](deployment-shapes.md) covers AWS Bedrock Agents, OpenAI Assistants, Azure AI Foundry, and Vertex AI Agent Engine. Dedicated [**Vertex AI**](agent-engine.md) walkthrough.
</div>

<div class="hopframe-card" markdown>
### I want to contribute
[**Developer guide**](developer.md) for the codebase walkthrough. [**Policies**](policies.md) for the policy resource model. Detection rules under [`content/`](https://github.com/jLuPSP/hopframe/tree/main/content) accept Apache 2.0 contributions.
</div>

</div>

## Status

Alpha. Suitable for design-partner pilots, internal evaluation, homelab and small-team production. Not yet hardened for regulated workloads without your own validation, multi-region active-active, or anything requiring a SOC 2 attestation. See [Roadmap](roadmap.md).

## License

[BSL 1.1](https://github.com/jLuPSP/hopframe/blob/main/LICENSE) on the code (converts to Apache 2.0 three years after each release). [Apache 2.0](https://github.com/jLuPSP/hopframe/tree/main/content) on the detection rules and benchmark corpus today. Built by [Jordan Lu](https://github.com/jLuPSP).

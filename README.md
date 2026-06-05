<p align="center">
  <a href="https://github.com/jLuPSP/hopframe"><img src="docs/screenshots/hopframe-banner.svg" alt="Hopframe: security mesh for agent traffic" width="100%"></a>
</p>

<p align="center">
  <a href="https://github.com/jLuPSP/hopframe/actions/workflows/ci.yaml"><img alt="ci" src="https://github.com/jLuPSP/hopframe/actions/workflows/ci.yaml/badge.svg"></a>
  <a href="https://github.com/jLuPSP/hopframe/releases"><img alt="release" src="https://img.shields.io/github/v/release/jLuPSP/hopframe?include_prereleases&sort=semver"></a>
  <img alt="status: alpha" src="https://img.shields.io/badge/status-alpha-orange">
  <img alt="license: BSL 1.1 (converts to Apache 2.0)" src="https://img.shields.io/badge/license-BSL%201.1-blue">
  <img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen">
</p>

<p align="center">
  <a href="https://jlupsp.github.io/hopframe/">Docs</a> &middot;
  <a href="docs/quickstart.md">Quickstart</a> &middot;
  <a href="docs/install-tiers.md">Install</a> &middot;
  <a href="docs/cli.md">CLI</a> &middot;
  <a href="docs/compare.md">Compare</a> &middot;
  <a href="docs/architecture.md">Architecture</a> &middot;
  <a href="https://github.com/jLuPSP/hopframe/issues/new">Report a bug</a>
</p>

# Hopframe

**A security mesh for agent traffic.** Sits inline on MCP and A2A protocol wires. Catches the attacks model-boundary guardrails can't see, and writes a hash-chained, signed audit record that an auditor can verify offline.

If your agents call MCP servers, talk to other agents, or run on someone's infrastructure, you have wires that Bedrock Guardrails, Model Armor, and Lakera Guard never inspect. A poisoned `tools/list` description goes straight to the model. A tool result with a leaked API key goes back to the agent. An A2A peer changes mid-task. None of it touches the prompt-response channel a model-layer filter sits on. **Hopframe sits one layer up, on the protocol wire, and catches all of it.**

```mermaid
flowchart LR
    Agent["agent<br/><i>Cursor, Claude Desktop,<br/>LangChain, custom</i>"]
    Hopframe["hopframe-sensor<br/><b>:7080/mcp</b><br/>detection + audit + policy"]
    MCP["your MCP server<br/><i>or A2A peer</i>"]
    Agent -- "JSON-RPC<br/>(tools/list, tools/call)" --> Hopframe
    Hopframe -- "forwards if allowed,<br/>blocks if not" --> MCP
    MCP -- "response<br/>(inspected before return)" --> Hopframe
    Hopframe -- "to agent<br/>(or BLOCKED)" --> Agent
```

<p align="center">
  <img src="docs/screenshots/demo.gif" alt="make demo: cinematic blind-spot story" width="780">
  <br/>
  <em>30 seconds. <code>make demo</code> boots the full stack and plays the attack story end-to-end.</em>
</p>

## What changes when you deploy this

- **Poisoned tool descriptions get blocked at the wire**, before the agent's model ever reads them. The sensor inspects every `tools/list` response and quarantines tools whose descriptions carry instruction-override patterns.
- **Cross-protocol leaks get caught.** An MCP tool returns sensitive data; the agent forwards it in an A2A task to an unallowlisted peer. Hopframe blocks the leak. No model-layer filter sees this; it spans two protocol hops.
- **Every event becomes evidence.** SHA-256 hash-chained log, optional Ed25519 per-record signatures, optional Sigstore Rekor anchoring. Hand a six-month report to a regulator and they re-walk the chain themselves. Selective disclosure: one record can go to an auditor without revealing the rest.
- **Editable policies, hot-reloaded.** "Block tool poisoning on the github MCP for tenant acme; warn on prompt injection elsewhere." Author in the UI or `POST /v1/policies`, dry-run against the last 1000 events, sensors apply on the next heartbeat with no restart.
- **Multi-tenant from day one.** Tokens are scope-bound to a tenant; reads filter, writes pin `event.tenant_id`. Same binary serves a homelab and a regulated tenant.

## See it before you install it

<p align="center">
  <a href="docs/screenshots/dashboard.png"><img src="docs/screenshots/dashboard.png" alt="Dashboard with events, blocked, warned, findings, sensor fleet, activity sparkline, top counterparties, recent blocks" width="780"></a>
</p>

<p align="center">
  <em>Operator dashboard at <code>/dashboard</code>. Every blocked attack, every audit record, every sensor's health on one screen.</em>
</p>

<table>
  <tr>
    <td width="50%"><a href="docs/screenshots/policies.png"><img src="docs/screenshots/policies.png" alt="Policies UI"></a><br/><em><strong>Policies.</strong> Author + dry-run + hot-reload. <code>/policies</code></em></td>
    <td width="50%"><a href="docs/screenshots/records.png"><img src="docs/screenshots/records.png" alt="Records UI"></a><br/><em><strong>Records.</strong> Per-record signature + Merkle proof, verified in your browser. <code>/records</code></em></td>
  </tr>
  <tr>
    <td><a href="docs/screenshots/sensors.png"><img src="docs/screenshots/sensors.png" alt="Sensors UI"></a><br/><em><strong>Sensor fleet.</strong> Heartbeat, applied policy version, drift. <code>/sensors</code></em></td>
    <td><a href="docs/screenshots/rules.png"><img src="docs/screenshots/rules.png" alt="Rules UI"></a><br/><em><strong>Rules.</strong> 59 detection rules across 5 categories, every regex inspectable. <code>/rules</code></em></td>
  </tr>
  <tr>
    <td colspan="2"><a href="docs/screenshots/audit.png"><img src="docs/screenshots/audit.png" alt="Audit UI"></a><br/><em><strong>Audit.</strong> Signed compliance exports with a chain-proof trailer. NDJSON / CSV. Verifiable offline by your auditor with no access to the control plane. <code>/audit</code></em></td>
  </tr>
</table>

## Run it

Pick the path that matches what you already have installed.

**With Go 1.25+** (recommended for the cinematic story; one-line install):

```bash
git clone https://github.com/jLuPSP/hopframe.git
cd hopframe
make demo                                       # see what it does (bundled stubs)
make run UPSTREAM=http://your-mcp-server:8080   # use it in front of your MCP
```

**With Docker** (no Go required; multi-stage Dockerfile compiles inside the build):

```bash
git clone https://github.com/jLuPSP/hopframe.git
cd hopframe
UPSTREAM=http://your-mcp-server:8080 docker compose up
```

After either, repoint your agent at `http://127.0.0.1:7080/mcp` instead of your MCP's URL. **The agent and the MCP server don't change**; Hopframe inspects every JSON-RPC message in between. Open `http://127.0.0.1:7090` for the UI.

**Modifiers** (work with both `make run` and `docker compose up`):

- `A2A_UPSTREAM=http://your-a2a-peer:8080` wires an A2A sensor on `:7081` (Docker: `docker compose --profile a2a up`).
- `ENTERPRISE=1` (make only, today): bearer auth, role tokens (viewer/editor/admin/owner), tenant scoping, signing, sample policies seeded. Tokens print on stdout. OIDC and Rekor stay off (external infra; see [`docs/install-tiers.md`](docs/install-tiers.md)).
- Drop `UPSTREAM` from the make path to use a bundled stub MCP and poke at the UI without any setup.

For Kubernetes, the [Helm chart](deploy/helm/hopframe/) covers production deployments. Pre-built binaries, multi-arch container images on `ghcr.io/jlupsp/hopframe`, and Sigstore-signed checksums publish on every release tag; see [Releases](https://github.com/jLuPSP/hopframe/releases). Full reference: [`docs/install-tiers.md`](docs/install-tiers.md), [CLI](docs/cli.md), [HTTP API](docs/api.md).

## Why this exists

Every AI security tool sits at the model boundary. Bedrock Guardrails, Model Armor, Lakera Guard, NeMo. They inspect the prompt going into the LLM and the response coming back. **One wire.**

Agents have other wires. The MCP tool description served by a server. The tool result that comes back. The A2A task envelope between agents. None of these traverse a model-layer filter, because they are not prompts; they are protocol messages. A poisoned `tools/list` description is read by the model directly, with nothing in the way.

Hopframe sits on those wires.

## Compared to Bedrock Guardrails, Lakera, Model Armor &middot; Runlayer, Operant, Lasso

**Different layer than the model-boundary players.** Bedrock Guardrails, Model Armor, Lakera Guard, NeMo Guardrails sit on the prompt-response channel. Hopframe sits one layer up on the protocol wire. **Stack them.** Most of the unique value is the protocol-layer surface a model-layer filter physically cannot see: tool poisoning at `tools/list`, cross-protocol taint, A2A drift, the audit chain.

**Different shape than the MCP gateway / agent security startups** that raised in 2025-2026 (Runlayer, Operant AI, Lasso Security, Solo.io agentgateway, IBM ContextForge, Cisco DefenseClaw, Invariant Labs / Snyk agent-scan). Of nine detection / audit surfaces Hopframe ships, **three have no published peer at all**: cross-protocol taint (MCP→A2A), A2A task drift, and MCP+A2A correlation on a single forensic timeline. Cryptographic audit (hash chain + Ed25519 + Sigstore Rekor) has one published peer — ArkForge — but it's SaaS-only, audit-only, and MCP-only; Hopframe ships detection and audit together, in your environment, with no per-call cost.

**Open and free where the SaaS players aren't.** Runlayer, Operant AI, and ArkForge are closed SaaS — your protocol traffic crosses their cloud and you cannot read the detection logic they apply to it. Lasso's "open-source" gateway POSTs traffic to `server.lasso.security` for classification, so the actual detection is closed and paid. Snyk's agent-scan is hybrid (local proxy + Snyk Evo SaaS reporting tier). Hopframe is **BSL 1.1 source-available today, Apache 2.0 in three years, with detection rules and benchmark corpus Apache 2.0 right now** — every rule readable, every detector running locally, fork-friendly. The only restriction is "no competing managed service," and that lifts on the Change Date. Solo.io agentgateway, Cisco DefenseClaw, and IBM ContextForge are also OSS, but ship less detection in-tree (gateway / admission-time scan rather than the inline four-layer pipeline + signed audit).

Full capability matrix and longer Q&A in [docs/compare.md](docs/compare.md).

## Concretely, what gets caught

- A tool result body contains `AKIAIOSFODNN7EXAMPLE` or a PEM private key. Hopframe flags it; if a policy says block, drops it before it reaches the agent.
- A `tools/list` description includes `<system>` tags or "ignore previous instructions" patterns. Quarantined; subsequent `tools/call` to the named tool short-circuits.
- An A2A task transitions from `submitted` straight to `completed`, skipping `working`. Or the counterparty changes mid-task. Both recorded.
- An MCP tool returns sensitive data; the agent forwards it to a different counterparty in an A2A task. Cross-protocol taint. Blocked.
- An attacker paraphrases an instruction-override into novel language the regex pack does not match. The heuristic classifier catches the feature-density signal anyway.

Four-layer detection: regex packs (sub-5µs) → heuristic feature-density classifier (sub-30µs) → optional LLM judge for the uncertain band (300-1500ms) → behavioral anomaly detection on the control plane (continuous). Inputs are NFKC-normalized and base64-decoded before matching, so the obvious bypasses fail.

Full capability list: [docs/capabilities.md](docs/capabilities.md).

## Status

Alpha. Honest about it.

- 22 Go packages tested under `-race`, 15 Python tests, 14 TypeScript tests, all green on every commit.
- Single-process control plane today. Postgres-backed HA is in [`docs/roadmap.md`](docs/roadmap.md) Phase 2C.
- Detection corpus is small (84 samples, F1 = 1.0). Treat as a floor; real-world traffic will surface gaps.
- Good for: design-partner pilots, internal evaluation, homelab and small-team production, anywhere you want pre-flight evidence on agent traffic.
- Not yet ready for: regulated workloads without your own validation, multi-region active-active, anything requiring a SOC 2 attestation.

If you deploy this somewhere real, **I want to hear what breaks.** Open an issue, or a [private security advisory](https://github.com/jLuPSP/hopframe/security/advisories/new) for security-sensitive reports. The fastest path from alpha to GA runs through the people who push it.

## Contributing

The most useful contribution is a detection rule paired with a benchmark sample that exercises it. See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome on rule packs, SDK adapters, doc fixes, and CI hardening.

## License & ownership

Copyright © 2026 **[Jordan Lu](https://github.com/jLuPSP)**. All rights reserved. "Hopframe" and the Hopframe logo are marks of Jordan Lu. See [NOTICE](NOTICE) for the full ownership statement.

Hopframe ships under **two licenses, applied to different directories**:

- The repository as a whole is **[Business Source License 1.1](LICENSE)**, with a Change Date three years after each release on which the code converts to **[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)**. BSL is source-available, not OSI-approved: you can read, run, fork, and modify the code for any purpose **except offering a competing managed service**. That restriction lifts on the Change Date and the release becomes Apache 2.0.
- The **detection content** under [`content/`](content/) and the **benchmark corpus** under [`bench/corpus/`](bench/corpus/) are **[Apache License 2.0 today](content/LICENSE)**. The rule pack and corpus are explicitly OSI-approved open source so they can be freely incorporated into other security tools, research papers, and detection benchmarks. Apache requires preserving the copyright + license notice; the "Hopframe" name stays.

There are no proprietary feature gates. The BSL "no competing managed service" reservation just keeps someone from reselling it wholesale as a hosted product before the Change Date; the code stays source-available for everyone else, and the whole thing converts to Apache 2.0 on schedule.

Security disclosures: open a [private security advisory](https://github.com/jLuPSP/hopframe/security/advisories/new). Everything else: [open an issue](https://github.com/jLuPSP/hopframe/issues).

Built by [Jordan Lu](https://github.com/jLuPSP). Detection-content format and contribution model follow the [OWASP](https://owasp.org/) tradition.

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
  <a href="docs/how-it-works.md">How it works</a> &middot;
  <a href="docs/deploy.md">Deploy</a> &middot;
  <a href="https://github.com/jLuPSP/hopframe/issues/new">Report a bug</a>
</p>

# Hopframe

**A security mesh for agent traffic.** Hopframe sits inline in the MCP and A2A data path. It catches the attacks model-boundary guardrails can't see. It writes a hash-chained, signed audit record that an auditor can verify offline.

Agents that call MCP servers or talk to other agents use protocol traffic that model-boundary guardrails do not inspect. A poisoned `tools/list` description can reach the model, a tool result can carry a leaked key, and an A2A peer can change mid-task. **Hopframe sits in that MCP and A2A data path so it can inspect each message before forwarding it.**

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
  <img src="docs/screenshots/demo.gif" alt="make demo running the full attack story end to end" width="780">
  <br/>
  <em>30 seconds. <code>make demo</code> boots the full stack and plays the attack story end-to-end.</em>
</p>

## What it does in the data path

- **Poisoned tool descriptions get blocked in the data path**, before the agent's model reads them. The sensor inspects every `tools/list` response and quarantines tools carrying instruction-override patterns.
- **Cross-protocol leaks get caught.** An MCP tool returns sensitive data; the agent forwards it in an A2A task to an unallowlisted peer. Hopframe blocks the leak. No model-layer filter sees this; it spans two protocol hops.
- **Every event becomes evidence.** The log uses SHA-256 hash chains, optional Ed25519 per-record signatures, and optional Sigstore Rekor anchoring. A regulator can re-walk the chain in a six-month report. Selective disclosure sends one record to an auditor without revealing the rest.
- **Editable policies, hot-reloaded.** "Block tool poisoning on the github MCP for tenant acme; warn on prompt injection elsewhere." Author policies in the UI or with `POST /v1/policies` and dry-run them against the last 1000 events. Sensors apply them on the next heartbeat with no restart.
- **Multi-tenant.** Tokens are scope-bound to a tenant; reads filter, writes pin `event.tenant_id`. Same binary serves a homelab and a regulated tenant.

## What it looks like

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
    <td><a href="docs/screenshots/rules.png"><img src="docs/screenshots/rules.png" alt="Rules UI"></a><br/><em><strong>Rules.</strong> 58 detection rules across 6 categories, every regex inspectable. <code>/rules</code></em></td>
  </tr>
  <tr>
    <td colspan="2"><a href="docs/screenshots/audit.png"><img src="docs/screenshots/audit.png" alt="Audit UI"></a><br/><em><strong>Audit.</strong> Signed compliance exports with a chain-proof trailer. NDJSON / CSV. Verifiable offline by your auditor with no access to the control plane. <code>/audit</code></em></td>
  </tr>
</table>

## Run it

**With Go 1.25+** (recommended):

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

After either, repoint your agent at `http://127.0.0.1:7080/mcp` instead of your MCP's URL. **The agent and the MCP server don't change.** Hopframe inspects every JSON-RPC message in between. Open `http://127.0.0.1:7090` for the UI.

**Modifiers** (work with both `make run` and `docker compose up`):

- `A2A_UPSTREAM=http://your-a2a-peer:8080` wires an A2A sensor on `:7081` (Docker: `docker compose --profile a2a up`).
- `SECURE=1` (make only, today) enables bearer auth, role tokens (viewer/editor/admin/owner), tenant scoping, signing, and seeded sample policies. Tokens print on stdout. OIDC and Rekor stay off (external infra; see [deploy docs](docs/deploy.md)).
- Drop `UPSTREAM` from the make path to use a bundled stub MCP and poke at the UI with no setup.

For Kubernetes, the [Helm chart](deploy/helm/hopframe/) covers production deployments. Every release tag publishes pre-built binaries, multi-arch container images on `ghcr.io/jlupsp/hopframe`, and Sigstore-signed checksums. See [Releases](https://github.com/jLuPSP/hopframe/releases) and the [deploy docs](docs/deploy.md).

## Why this exists

Every AI security tool sits at the model boundary, inspecting the prompt going into the LLM and the response coming back. Agents have other data-path traffic: the MCP tool description served by a server, the tool result that comes back, and the A2A task envelope between agents. These are protocol messages rather than prompts, so no model-layer filter sees them.

The build decisions and a read of the landscape are in a case study: [Building Hopframe](https://jlu.dev/blog/building-hopframe/).

## Where it sits in the landscape

The short version of the landscape, as of mid-2026, follows.

The agent-security space sorts into four layers: model-boundary guardrails on the prompt/response channel (Bedrock Guardrails, Model Armor, Lakera, NeMo), MCP/agent gateways doing admission and routing, inline protocol-wire inspection, and audit/provenance. Hopframe combines the last two, which differentiates it. Model-boundary tools work at a different layer; stack them with Hopframe.

**The closest peer is [Solo.io's agentgateway](https://www.solo.io/products/agentgateway).** It is a credible, open-source (Apache 2.0, Linux Foundation) proxy. Like Hopframe, it sits inline on both MCP and A2A with no code changes. It inspects MCP tool calls beyond the prompt through tool-server fingerprinting, versioning, and runtime policy against poisoning and rug-pulls. If you want a vendor and a roadmap behind it, look there first. Hopframe instead uses a four-stage content pipeline (regex, heuristic classifier, LLM judge, behavioral). Its guardrails run on protocol content as well as the model boundary. It ships a tamper-evident audit log (hash chain + Ed25519 + Sigstore Rekor). Agentgateway's "verifiable audit trail" claim did not hold up under checking.

**I could not find a peer for cross-protocol data taint** (an MCP tool result leaking into an A2A task). I found none for A2A task-state or counterparty drift mid-task, or a unified MCP+A2A forensic timeline. That is "as far as I looked," not a proof of absence. The 2025-2026 startup wave (Runlayer, Operant AI, Lasso, Cisco AI Defense, and others) moves fast. I could not verify several of its tools.

**The threat model is no longer speculative.** Since I started this, OWASP shipped a [Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). Its ASI07 names insecure inter-agent (A2A and MCP) communication. Its [MCP Top 10](https://owasp.org/www-project-mcp-top-10/) calls out tool poisoning (MCP03) and lack of audit and telemetry (MCP08). It recommends the same SHA-256-hashed, append-only audit that Hopframe implements.

## Concretely, what gets caught

- A tool result body contains `AKIAIOSFODNN7EXAMPLE` or a PEM private key. Hopframe flags it. If a policy says block, Hopframe drops it before it reaches the agent.
- A `tools/list` description includes `<system>` tags or "ignore previous instructions" patterns. Quarantined; subsequent `tools/call` to the named tool short-circuits.
- An A2A task transitions from `submitted` straight to `completed`, skipping `working`. Or the counterparty changes mid-task. Both recorded.
- An attacker paraphrases an instruction-override into novel language the regex pack does not match. The heuristic classifier catches the feature-density signal anyway.

Four-layer detection runs through regex packs (sub-5µs) → heuristic feature-density classifier (sub-30µs) → optional LLM judge for the uncertain band (300-1500ms) → behavioral anomaly detection on the control plane (continuous). Hopframe NFKC-normalizes and base64-decodes inputs before matching, so the obvious bypasses fail.

## Status

Alpha.

- 22 Go packages tested under `-race`, 15 Python tests, 14 TypeScript tests, green on every commit.
- Single-process control plane today. Postgres-backed HA is not built yet.
- The detection corpus is small (95 samples, F1 = 1.0; the perfect score reflects the corpus size). Treat it as a floor; real traffic will surface rules I have not written.
- Hopframe fits evaluation, a homelab, a small team, or anywhere you want evidence on agent traffic before you trust it. Validate it yourself before a regulated workload.

If you run it somewhere real, I would like to know what broke.

## Contributing

The most useful contribution is a detection rule paired with a benchmark sample that exercises it. See [CONTRIBUTING.md](CONTRIBUTING.md). PRs are welcome on rule packs, SDK adapters, doc fixes, and CI hardening.

## License & ownership

Copyright © 2026 **[Jordan Lu](https://github.com/jLuPSP)**. All rights reserved. "Hopframe" and the Hopframe logo are marks of Jordan Lu. See [NOTICE](NOTICE) for the full ownership statement.

Hopframe ships under **two licenses, applied to different directories**:

- The repository as a whole is **[Business Source License 1.1](LICENSE)**. The code converts to **[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)** on a Change Date three years after each release. BSL is source-available and not OSI-approved. You can read, run, fork, and modify the code for any purpose **except offering a competing managed service**.
- The **detection content** under [`content/`](content/) and the **benchmark corpus** under [`bench/corpus/`](bench/corpus/) are **[Apache License 2.0 today](content/LICENSE)**, OSI-approved open source. They can be freely incorporated into other security tools, research papers, and detection benchmarks. Apache requires preserving the copyright + license notice. The "Hopframe" name stays.

There are no proprietary feature gates. The BSL reservation keeps someone from reselling Hopframe as a hosted product before the Change Date.

Security disclosures: open a [private security advisory](https://github.com/jLuPSP/hopframe/security/advisories/new). Everything else: [open an issue](https://github.com/jLuPSP/hopframe/issues).

Detection-content format and contribution model follow the [OWASP](https://owasp.org/) tradition.

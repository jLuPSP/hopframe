# Changelog

All notable changes to Hopframe are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-29

### Added

- **Gateway data-plane surfaces.** Two new ways to run Hopframe over the same detection pipeline. `mcp-extauthz` is an Envoy HTTP external-authorization adapter, so any Envoy-based gateway (Envoy, Istio, Gloo, Emissary) can get an allow/deny decision on inbound MCP with no per-gateway code. `mcp-gateway` is a native multiplexer that fronts many MCP upstreams at one address with full inline fidelity and shared quarantine/taint state. See [docs/index.md](docs/index.md) for the deploy paths and `deploy/labs/extauthz-e2e/` for a real-Envoy end-to-end lab.
- **Python SDK release path prepared.** The tag workflow builds the `hopframe` package and is ready to publish it through PyPI Trusted Publishing after the one-time PyPI project setup.

### Changed

- Retired the price-tier vocabulary, since the repo ships every feature under one license with no gates. The docs now describe deployment **modes** (Demo / Homelab / Secured) instead of tiers; the make flag `ENTERPRISE=1` is now `SECURE=1`; the preset `examples/config/enterprise.env` is now `secured.env`; and `docs/install-tiers.md` is now `docs/install.md`.

### Fixed

- **Docker base images** for the compose deploy bumped to `golang:1.25-alpine`; the `1.23` pin no longer satisfied `go.mod`'s `go >= 1.25` under alpine's `GOTOOLCHAIN=local`.
- **`/healthz` answers `HEAD`** as well as `GET` on the ext_authz and gateway surfaces, so spider-style health probes do not read as unhealthy.

## [0.1.1] - 2026-06-12

Hardening release. Makes cross-protocol taint actually work in a single deployable,
adds real A2A task-drift detection, and keeps the shipped detection defaults calibrated.

### Added

- **Combined `sensor` binary.** Runs the MCP and A2A proxies in one process over a
  shared detection pipeline, so they share one taint tracker. The split `mcp-sensor` /
  `a2a-sensor` binaries each keep taint state in their own memory, which means a tool
  result tagged on the MCP wire is invisible to the A2A wire. The combined sensor closes
  that gap: an MCP tool result reaching an A2A peer is recognized and blocked within one
  binary. (Cross-replica taint sharing via the control plane is still future work.)
- **A2A task-drift detection.** The A2A sensor now validates a task's self-declared
  `x_state_history` (flags `submitted -> completed` with no `working`, and illegal
  transitions) and checks the responder against the contracted counterparty
  (`x_responder` vs `x_contracted`). New `policy.block_task_drift` (default `false`,
  detect-only) opts a deployment in to blocking these.

### Changed

- **Taint matching is transformation-robust.** The taint tracker now shingles over the
  canonical views of a value (NFKC + zero-width strip, plus base64-decoded payloads),
  the same normalization the rule engine uses. A secret tagged on the MCP wire is now
  recognized even if the agent base64-encodes or Unicode-obfuscates it before forwarding.

### Fixed

- **Counterparty false positive.** Task counterparty tracking no longer keys off the
  request's ephemeral source address, which previously raised a spurious
  `task.counterparty_changed` on every new connection of a multi-call task. The
  authoritative peer-swap signal is the declared `x_responder` vs `x_contracted` mismatch.

## [0.1.0] - 2026-04-27

First tagged alpha. Suitable for design-partner pilots, internal evaluation, homelab and small-team production. Not yet hardened for regulated workloads without the operator's own validation, multi-region active-active, or anything requiring a SOC 2 attestation.

### Added: Inline detection

- MCP and A2A sensors. HTTP, stdio, and SSE for MCP; HTTP for A2A.
- Four-layer detection pipeline. Regex packs (Layer 1, sub-5µs), heuristic feature-density classifier (Layer 2, sub-30µs), optional LLM judge (Layer 3, 300-1500ms; OpenAI Chat Completions wire format so OpenAI / Anthropic-compat / Ollama / vLLM / LiteLLM all work), behavioral anomaly detector (Layer 4, continuous on the control plane).
- 59 detection rules across `prompt-injection`, `tool-poisoning`, `credential-exfiltration`, `pii-leakage`, `policy`, and `a2a-card`.
- NFKC normalization and base64 unwrapping before matching, so zero-width characters, homoglyphs, and base64-wrapped payloads do not trivially bypass.
- Cross-protocol taint tracking. Tool-call results are fingerprinted; subsequent A2A task messages on the same `agent_run_id` are checked for reuse and blocked when reaching an unallowlisted peer.
- Tool quarantine. A high or critical finding on a `tools/list` description quarantines the tool; subsequent `tools/call` to that tool short-circuits at the wire.
- A2A task drift detector. Catches illegal state transitions (e.g. `submitted → completed` skipping `working`), mid-task counterparty change, and task-id reuse across counterparties.
- Per-counterparty risk scoring with severity weighting and time decay.

### Added: Operator UI and API

- Operator UI: live event stream (`/`), time-series dashboards (`/dashboard`), policy authoring with dry-run preview (`/policies`), sensor fleet inventory (`/sensors`), per-record signature inspector that verifies the Ed25519 signature in-browser via SubtleCrypto (`/records`), rule-pack browser (`/rules`), signed-export builder (`/audit`), users + API tokens (`/settings`).
- Versioned `/v1/*` HTTP API. Everything the UI does maps to a CRUD-able endpoint.
- User management. Bcrypt-hashed local accounts with viewer / editor / admin / owner roles; session-cookie login; bootstrap admin via env var on first boot.
- API tokens as first-class resources. Mint via `POST /v1/tokens`, list via `GET /v1/tokens`, revoke via `DELETE /v1/tokens/{id}`. Secret value shown once at mint; only the SHA-256 hash persists.
- RBAC roles: viewer / editor / admin / owner. Token-to-role binding via `HOPFRAME_ROLE_TOKENS`. Legacy alias names (`policy_author`, `tenant_admin`, `super_admin`) accepted on input and normalized to canonical roles. Composes with per-tenant token scoping.
- Per-tenant token scoping. `HOPFRAME_TENANT_TOKENS=token1:tenantA,token2:tenantB` binds bearer tokens to tenants. Reads filter to the bound tenant; writes pin `event.tenant_id`. The legacy `HOPFRAME_API_TOKEN` remains the admin scope.
- OIDC SSO. `/auth/login` redirects to the IdP; `/auth/callback` exchanges the code for tokens, verifies the id_token signature against the IdP's JWKS (RS256 / RS384 / RS512 / ES256 / ES384) with cache and rotation, and mints a session bearer with a role pulled from group claims.
- Per-IP token-bucket rate limiter on `/v1/*`, opt-in via `HOPFRAME_RATE_LIMIT_RPS`. Returns 429 with `Retry-After: 1` when exceeded.
- Prometheus `/metrics` endpoint. Counters for ingested events (by action, severity), HTTP requests (by method, path, status), policy changes, and rate-limit rejections. Gauges for uptime and chain head sequence. Hand-rolled, no new direct dependencies.
- `--version` flag on every operator-facing binary, stamped at link time by goreleaser.

### Added: Policy plane

- Editable, hot-reloadable policies as first-class control-plane resources. CRUD API at `/v1/policies`, read endpoint for sensors at `/v1/policies/active`, dry-run preview at `/v1/policies/{id}/preview` against recent traffic.
- Hierarchy resolution most-specific-wins (server > sensor > tenant > org default).
- Sensor-side hot reload via heartbeat. A policy version mismatch triggers refetch and atomic snapshot swap.
- Every policy mutation recorded as a synthetic event on the audit chain so changes are visible alongside protocol traffic.

### Added: Cryptographic audit

- Hash-chained append-only audit log. Continuous integrity check on read and on rotation.
- Per-record Ed25519 signing. `/v1/records/{seq}` returns the canonical bytes, the signature, and a Merkle proof tying the record to a snapshot of recent records. Selective disclosure: a single record can go to an auditor without exposing the rest.
- Signed compliance exports. CSV and NDJSON exports at `/v1/events.{csv,ndjson}` carry a chain-proof trailer bound to the head hash at export time.
- Sigstore Rekor anchoring. `pkg/audit.Rekor` posts the chain head to a Rekor instance on demand; `/v1/audit/anchor` triggers from operators. The anchor itself is recorded on the chain so the witness becomes part of the trail.
- Rule-version provenance. Every rule's compile produces a content hash; every finding includes the hash in metadata so an auditor can re-run the rule on the same input and confirm the same finding.
- `hopframe-export` CLI. Standalone binary that pulls records from a control plane, signs each with the operator's key, writes a manifest with chain head + Merkle root + per-record signatures, and a `VERIFY.md` the receiver follows offline without contacting the control plane.

### Added: Sensors and content

- Sensor fleet inventory. Sensors heartbeat to `/v1/sensors/heartbeat` with version + applied policy version + applied content version. `/v1/sensors` lists the fleet with stale and drift markers.
- OTA detection-content delivery. Versioned manifest at `/v1/content/manifest`; per-file fetch at `/v1/content/{name}` with a SHA-256 hash header. Sensors compare manifest version on heartbeat and fetch only changed files.
- stdio MCP sensor (`mcp-stdio-sensor`). Drop-in for Claude Desktop, Cursor, Continue, and `claude-code` configurations.
- Webhook and Splunk HEC exporters. HMAC-signed payloads, retry with backoff, durable on-disk spool.

### Added: Distribution

- Multi-stage `Dockerfile` at repo root. Compiles every operator binary inside the build, lands on `gcr.io/distroless/static-debian12:nonroot`. Works for direct `docker build .` (no Go install required) and for the CI publish pipeline.
- `docker-compose.yml` for one-command boot. `UPSTREAM=http://your-mcp:8080 docker compose up` brings up control-plane + sensor against a real MCP. `--profile a2a` adds an A2A sensor.
- Helm chart at `deploy/helm/hopframe/`. Control plane + MCP sensor, persistent volumes, configurable retention, exposes every relevant `HOPFRAME_*` env var (auth tokens, signing key, policy path, content root, rate limit, OIDC, LLM judge).
- Two-target make UX. `make demo` (cinematic story, bundled stubs) and `make run UPSTREAM=...` (Hopframe in front of your real MCP). `ENTERPRISE=1` modifier turns on the multi-tenant + RBAC + signing surface with auto-minted tokens printed on stdout.
- Multi-arch container images. `ghcr.io/jlupsp/hopframe:0.1.0` and `:latest` for `linux/amd64` and `linux/arm64`, cosign-signed via GitHub OIDC keyless.
- Pre-built binaries for `linux`, `darwin`, `windows` × `amd64`, `arm64`, attached to the GitHub Release with SHA-256 checksums, Syft SBOMs, and cosign-signed checksum files.

### Added: SDKs

- Python SDK at `sdk/python/`. Sync `Hopframe` client and asyncio-native `AsyncHopframe` (batch emit, exponential-backoff retry, drop-on-permanent-error, pluggable transport). Framework adapters for LangChain, LangGraph, CrewAI, and OpenAI Assistants. Dependency-free at the base layer.
- TypeScript SDK at `sdk/typescript/` (`@hopframe/sdk`). Dependency-free client mirroring the Python shape. Adapters for Vercel AI SDK (`/ai-sdk`), LangChainJS (`/langchainjs`), Mastra (`/mastra`), and the raw MCP transport (`/mcp`).
- Both SDKs use the same wire schema as the Go sensors so events from any producer land on the same control-plane timeline.

### Added: Validation and benchmarks

- `make validate VALIDATE_CMD="..."` runs the standard MCP handshake against any stdio server, including a deliberately malicious request, and writes a markdown report.
- Compatibility matrix. End-to-end validated against `@modelcontextprotocol/server-everything`, `-filesystem`, `-memory`, and `-sequential-thinking`.
- Public benchmark corpus at `bench/corpus/v1.jsonl`, 84 self-curated samples. Precision 1.000, Recall 1.000, F1 1.000 on this corpus. Larger public-attack-library numbers (HarmBench, JailbreakBench, AgentDojo) tracked for a follow-up release.
- Latency budget. ~115k evals/sec on a laptop, p50 ~30µs, p99 ~160µs.

### Added: Documentation

- Threat model (`docs/threat-model.md`).
- Architecture overview with Mermaid diagrams (`docs/architecture.md`).
- Vertex AI Agent Engine deployment shapes (`docs/agent-engine.md`).
- Capability matrix vs Runlayer / Operant AI / Lasso / Solo.io agentgateway / Cisco DefenseClaw / IBM ContextForge in `docs/compare.md`.
- Roadmap covering the 12-month plan (`docs/roadmap.md`).

### Added: Repo hygiene

- CI workflow (`.github/workflows/ci.yaml`): build + race tests + vet on push and PR.
- Release workflow (`.github/workflows/release.yaml`): goreleaser binaries + multi-arch container publish on `v*` tag push.
- Docs workflow (`.github/workflows/docs.yaml`): MkDocs build + deploy to GitHub Pages.
- PR template (`.github/PULL_REQUEST_TEMPLATE.md`) with DCO sign-off check.
- Issue templates (`.github/ISSUE_TEMPLATE/{bug,detection-rule,feature}.md`) with security/commercial routing in `config.yml`.
- Dependabot config (`.github/dependabot.yml`) for gomod, npm, pip, github-actions, docker.

### Notes

- License: [BSL 1.1](LICENSE) with Change Date three years after each release; converts to Apache 2.0 on that date.
- Owner: Jordan Lu. Full ownership notice in [NOTICE](NOTICE).
- Source-available, not OSI-approved open source. Detection content (`content/`) and benchmark corpus (`bench/corpus/`) are released without the production-use restriction in the BSL.
- There are no proprietary feature gates.

[Unreleased]: https://github.com/jLuPSP/hopframe/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jLuPSP/hopframe/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jLuPSP/hopframe/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jLuPSP/hopframe/releases/tag/v0.1.0

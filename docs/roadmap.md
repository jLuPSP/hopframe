# Hopframe roadmap

This document is the spine of what Hopframe is building toward and the order it gets built. It is meant to hold for the next 12 months of solo nights-and-weekends pace. It will be updated as work lands and as design partners reshape priorities.

## Status snapshot

The first delivery cycle landed the kernel of all three pillars in v0.1. The remaining roadmap is either polish on what shipped, or the explicitly deferred work that requires real infrastructure and design-partner input (HA Postgres, OIDC integration testing against a real IdP, SOC 2 Type II, cryptographic per-tenant scoping).

| Phase | Status |
| --- | --- |
| 1A Policy CRUD API | Shipped |
| 1B Sensor pull + hot reload | Shipped |
| 1C Hierarchy resolver | Shipped |
| 1D Dry-run preview | Shipped |
| 1E Authoring UI | Deferred |
| 2A RBAC roles | Shipped |
| 2A OIDC | Skeletal (no JWKS verify) |
| 2B Sensor fleet inventory | Shipped |
| 2C HA Postgres | Deferred |
| 2D Authoring UI maturation | Deferred |
| 2E OTA content delivery | Shipped |
| 2F SOC 2 Type II | Deferred |
| 3A Rekor anchoring | Shipped |
| 3B Per-record signing + Merkle | Shipped |
| 3C Long-term archival | Deferred |
| 3D Forensic-export CLI | Shipped |
| 3E Rule-version provenance | Shipped |
| 3F Cryptographic per-tenant scoping | Deferred |

## What we are building toward

Three pillars together, undefended by any single tool today:

1. **Editable, adjustable policies at the org and MCP-server level.** Operators decide what gets monitored, warned, or blocked. Policies are versioned, hierarchical (org default, tenant override, MCP-server override), and distributable to sensors without redeploying binaries.
2. **Enterprise-grade management and control plane.** RBAC, SSO, multi-tenant administration, sensor fleet inventory, HA on a real database, SOC 2 Type II for the managed offering.
3. **Cryptographic audit-grade evidence.** Hash-chained log, signed exports with chain proofs, externally witnessed timestamps, per-record signing for selective disclosure, forensic export shapes that SOC 2 and HIPAA auditors accept.

Closed competitors do parts of pillar 1 inside their own cloud (Bedrock Guardrails, Model Armor) but lock customers to a vendor and do not speak MCP/A2A semantics. Open competitors (NeMo Guardrails, Garak, LLM-Guard) give parts of pillar 1 but no enterprise control plane and no cryptographic audit. MCP gateways do routing, not security. The intersection of all three pillars is undefended, and that is the wedge.

The rest of this doc maps each pillar to what exists today, what is missing, and a sequenced plan to ship the missing pieces.

## Sizing legend

Estimates assume a single staff IC working nights and weekends, not full-time.

| Size | Effort |
| --- | --- |
| S | One weekend |
| M | Two to four weekends |
| L | Two months of evenings |
| XL | A quarter of focused effort |

## Pillar 1: Editable, adjustable policies

A detection rule and a policy are different things. A **rule** matches: "this regex hits this field." A **policy** disposes: "for tenant X on the github MCP server, when rule R fires, block in production but only warn in staging."

Today Hopframe ships rules in YAML under `content/<category>/`, distributes them via the Helm chart, and reloads them on sensor restart. Operators can override the bundle by mounting a different ConfigMap. That works for "configurable" but not for "editable enterprise policy." The product needs policy as a separately addressable resource, mutable through the control plane, not through git commits.

### What is missing

- **Policy resource model.** A `Policy` is a named binding of (rule selector, scope, disposition, mode). Stored in the control plane, queryable, mutable, versioned.
- **Policy CRUD API.** `POST /v1/policies`, `GET /v1/policies/{id}`, `PATCH /v1/policies/{id}`, `DELETE /v1/policies/{id}`. Bound to the existing tenant scope.
- **Policy hierarchy.** Org-level default, tenant-level override, MCP-server-level override. Most-specific wins. Conflict resolution documented.
- **Policy distribution.** Sensors fetch active policy at boot and on a heartbeat; the control plane pushes invalidation events when a policy changes.
- **Hot reload.** Sensor swaps in the new policy without dropping in-flight connections.
- **Dry-run / preview.** Apply a policy in monitor mode against the last hour of recorded traffic and show what it would have caught. Required before anyone trusts a "block" disposition.
- **Policy versioning + audit.** Every policy change is a new version, written to the audit log itself.
- **Authoring UI.** Operators select rules from the catalog, set disposition and scope, save. Diff view against current.

### Sequence

| Phase | What | Size |
| --- | --- | --- |
| 1A | Policy resource model + CRUD API. Server-side only. | M |
| 1B | Sensor pulls active policy from control plane on boot + heartbeat. Hot reload without restart. | M |
| 1C | Policy hierarchy + scope evaluation. Most-specific-wins resolver. | S |
| 1D | Dry-run / preview against recent traffic. | M |
| 1E | Authoring UI. | L |

Phases 1A through 1C are the minimum viable policy plane. 1D is the difference between "policy exists" and "operators are willing to flip a policy to block in production."

## Pillar 2: Enterprise-grade management and control plane

Today the control plane is a single-process Go binary with bearer-token auth, per-tenant token scoping, Prometheus `/metrics`, optional per-IP rate limiting, and an embedded web UI. That is the alpha shape. Enterprise operators expect a different surface.

### What is missing

- **RBAC.** Read-only viewer, policy author, admin, super-admin (cross-tenant). Token scopes mapped to roles, not only to tenants.
- **SSO.** OIDC at minimum (Okta, Auth0, Azure AD, Google Workspace). SAML for traditional enterprises. Group-to-role mapping driven by IdP claims.
- **Multi-tenant administration UI.** Tenant lifecycle: create, archive, transfer, delete. Per-tenant dashboards. Per-tenant settings (retention, exporter config, policy scope).
- **Sensor fleet inventory.** Every sensor connected, its version, its active policy version, last-heartbeat. Force-update. Configuration-drift detection: "sensor S is running policy v17 but the active version is v19."
- **High availability control plane.** Multiple instances behind a load balancer. Audit log behind a real database (Postgres for transactional, ClickHouse for analytical reads). Hash-chain integrity preserved across instances.
- **Backup and restore.** Documented procedures for audit log + policy state. Tested runbook with RTO/RPO numbers.
- **Disaster recovery posture.** Per deployment shape. What to do when a region goes down.
- **Rolling upgrades.** Sensors upgrade without dropping inline traffic. Control-plane upgrades preserve the audit chain.
- **Over-the-air content delivery.** Detection-content updates without redeploying the binary. Signed content bundles fetched from a registry.
- **SOC 2 Type II for the managed offering.** Auditor engagement, control catalog, evidence collection. Months of work; gated on first paying design partner.

### Sequence

| Phase | What | Size |
| --- | --- | --- |
| 2A | RBAC + OIDC SSO. Role-scoped tokens. | L |
| 2B | Sensor fleet inventory + heartbeat + version reporting. | M |
| 2C | HA control plane on Postgres. Audit-chain semantics preserved across instances. | XL |
| 2D | Authoring UI maturation (overlaps Phase 1E). | L |
| 2E | OTA detection-content delivery channel. | M |
| 2F | SOC 2 Type II. | XL+ |

Phase 2C is the single biggest chunk in the roadmap. It is the migration from "alpha that runs on a laptop" to "regulated buyer can run this in production." Defer it until at least one design partner has committed to a pilot, so the schema and ops shape can be informed by a real deployment.

## Pillar 3: Cryptographic audit-grade evidence

Today: hash-chained NDJSON log under `control-plane/store/`, `/v1/verify` walks the chain on demand, signed CSV and NDJSON exports carry a chain-proof trailer bound to the head hash at export time. That is the alpha. Enterprise compliance teams want more.

### What is missing

- **External timestamping.** Each chain rotation anchors to a public transparency log (Sigstore Rekor). The timestamp is independently witnessed rather than only claimed by Hopframe itself.
- **Per-record signing.** Distinct from chain hash. Lets a customer share a single record with an auditor without revealing the rest of the log.
- **Selective disclosure via Merkle proofs.** Customer reveals a subset of records and proves the rest exist without showing them.
- **Long-term archival.** Default retention is 90 days. Archive older records to object storage with chain integrity preserved across the rotation boundary, not only the live log.
- **Forensic export shapes.** "Give me everything for tenant X between dates Y and Z, signed by us, with chain proof and selective Merkle proof, in a format SOC 2 / HIPAA auditors accept." One CLI command.
- **Rule-version provenance.** Every finding cites the exact rule version that produced it. Reproducibility: re-run rule + input on a different machine and get the same finding.
- **Cryptographic per-tenant scoping.** Tenant-A records cannot be decrypted without tenant-A's key. Today scoping is access-control; eventually it should be cryptographic so a control-plane operator cannot read tenant data without authorization.

### Sequence

| Phase | What | Size |
| --- | --- | --- |
| 3A | Rekor anchoring on chain rotation. | M |
| 3B | Per-record signing + selective Merkle disclosure. | L |
| 3C | Long-term archival to object storage with chain-preserving boundary. | M |
| 3D | Forensic-export CLI. | S |
| 3E | Rule-version provenance baked into findings. | S |
| 3F | Cryptographic per-tenant scoping. | XL |

3D is small and high-leverage. It is the artifact a compliance buyer holds in their hand. Worth shipping early.

## How to sequence across pillars

Solo nights-and-weekends pace, twelve months. Each quarter boundary should produce a deployable thing a design partner can use.

**Months 1 through 3.** Phase 1A + 1B + 1C: policy CRUD, distribution, hierarchy. Plus Phase 3D: forensic-export CLI. These two together get a design partner conversation past "interesting demo" into "we would actually run this."

**Months 4 through 6.** Phase 2A: RBAC + OIDC. Phase 1D: dry-run / preview. Phase 3A: Rekor anchoring. End-state: a regulated buyer can install Hopframe, configure policies through SSO with role-scoped tokens, preview what changes would do before applying them, and produce externally witnessed audit evidence.

**Months 7 through 9.** Phase 2B: sensor fleet inventory. Phase 2C kickoff: HA control plane on Postgres. Phase 1E: authoring UI v1. Phase 3E: rule-version provenance. End-state: pilot deployment at a design partner.

**Months 10 through 12.** Phase 2C completion. Phase 2E: OTA content delivery. Phase 3B: per-record signing + selective disclosure. Phase 2F kickoff: SOC 2 Type II engagement. End-state: paid managed offering ready for a second customer.

This sequence buys a usable product at each quarter boundary. It defers the most expensive pieces (HA migration, SOC 2) until after design-partner validation, so a quarter is not burned on infra nobody asked for.

## What this roadmap is not

- **Not a VC-scale plan.** Solo, nights and weekends. If a design partner does not materialize after Months 1 through 6, the right move is to slow, talk to more buyers, or pivot, not to ship more code.
- **Not a license to overbuild.** Each pillar has a minimum viable shape. Phase 2C does not start before Phase 1A is done. Phase 3F does not start before there is a paying customer asking for it.
- **Not a feature manifest.** The through-line is the three pillars. Anything that does not move one of them forward is a distraction in this window. Detection content expansion (which is on the v0.1 gap list) is in scope when it strengthens pillar 1, not as a goal in itself.

## Out of this roadmap

These appear elsewhere on the v0.1 gap list and are not part of the three-pillar core:

- TypeScript / JavaScript SDK. Reach into the Node MCP ecosystem. Strategic but separable from the three pillars; gets its own track.
- Public-corpus benchmarks (HarmBench, JailbreakBench, AgentDojo). Credibility content; runs in parallel.
- Layer 3 LLM judge wired in as an optional detector. Detection capability; runs in parallel.
- Trademark and naming work. One-time, blocking on louder publishing.

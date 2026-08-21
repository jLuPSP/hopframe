# Hopframe roadmap

This document defines what Hopframe is building and the build order. It covers the next 12 months at a solo nights-and-weekends pace. Work and design-partner feedback will reshape the priorities.

## Status snapshot

The first delivery cycle landed the core of all three pillars in v0.1. The remaining roadmap covers polish on shipped work and deferred work that requires real infrastructure and design-partner input. Deferred work includes HA Postgres, OIDC integration testing against a real IdP, SOC 2 Type II, and cryptographic per-tenant scoping.

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

Hopframe combines three pillars that no single tool defends today:

1. **Editable, adjustable policies at the org and MCP-server level.** Operators decide what gets monitored, warned, or blocked. Policies are versioned and hierarchical (org default, tenant override, MCP-server override). Sensors receive them without binary redeployment.
2. **Enterprise-grade management and control plane.** This pillar includes RBAC, SSO, multi-tenant administration, sensor fleet inventory, HA on a real database, and SOC 2 Type II for the managed offering.
3. **Cryptographic audit-grade evidence.** This pillar includes a hash-chained log, signed exports with chain proofs, externally witnessed timestamps, per-record signing for selective disclosure, and forensic export shapes that SOC 2 and HIPAA auditors accept.

Closed competitors do parts of pillar 1 inside their own cloud (Bedrock Guardrails, Model Armor). They lock customers to a vendor and do not speak MCP/A2A semantics. Open competitors (NeMo Guardrails, Garak, LLM-Guard) provide parts of pillar 1 without an enterprise control plane or cryptographic audit. MCP gateways handle routing. No tool defends the intersection of all three pillars.

The rest of this document maps each pillar to current work, missing work, and a sequence for shipping the missing pieces.

## Sizing legend

Estimates assume a single staff IC working nights and weekends.

| Size | Effort |
| --- | --- |
| S | One weekend |
| M | Two to four weekends |
| L | Two months of evenings |
| XL | A quarter of focused effort |

## Pillar 1: Editable, adjustable policies

A detection rule and a policy serve different functions. A **rule** matches a regex against a field. A **policy** determines the response: "for tenant X on the github MCP server, when rule R fires, block in production but only warn in staging."

Today Hopframe ships rules in YAML under `content/<category>/`, distributes them via the Helm chart, and reloads them on sensor restart. Operators can override the bundle by mounting a different ConfigMap. That approach provides configuration. Editable enterprise policy requires a separately addressable resource that operators can change through the control plane.

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

Phases 1A through 1C form the minimum viable policy plane. 1D gives operators the confidence to change a policy to block in production.

## Pillar 2: Enterprise-grade management and control plane

Today the control plane is a single-process Go binary with bearer-token auth, per-tenant token scoping, Prometheus `/metrics`, optional per-IP rate limiting, and an embedded web UI. This is the alpha shape. Enterprise operators expect a different surface.

### What is missing

- **RBAC.** Read-only viewer, policy author, admin, super-admin (cross-tenant). Token scopes map to roles as well as tenants.
- **SSO.** OIDC at minimum (Okta, Auth0, Azure AD, Google Workspace). SAML for traditional enterprises. Group-to-role mapping driven by IdP claims.
- **Multi-tenant administration UI.** Tenant lifecycle: create, archive, transfer, delete. Per-tenant dashboards. Per-tenant settings (retention, exporter config, policy scope).
- **Sensor fleet inventory.** The inventory shows every connected sensor, its version, its active policy version, and its last heartbeat. It supports force-update and configuration-drift detection: "sensor S is running policy v17 but the active version is v19."
- **High availability control plane.** Multiple instances behind a load balancer. Audit log behind a real database (Postgres for transactional, ClickHouse for analytical reads). Hash-chain integrity preserved across instances.
- **Backup and restore.** Documented procedures for audit log + policy state. Tested runbook with RTO/RPO numbers.
- **Disaster recovery posture.** Per deployment shape. What to do when a region goes down.
- **Rolling upgrades.** Sensors upgrade without dropping inline traffic. Control-plane upgrades preserve the audit chain.
- **Over-the-air content delivery.** Detection-content updates without redeploying the binary. Signed content bundles fetched from a registry.
- **SOC 2 Type II for the managed offering.** This requires auditor engagement, a control catalog, and evidence collection. It takes months of work and is gated on the first paying design partner.

### Sequence

| Phase | What | Size |
| --- | --- | --- |
| 2A | RBAC + OIDC SSO. Role-scoped tokens. | L |
| 2B | Sensor fleet inventory + heartbeat + version reporting. | M |
| 2C | HA control plane on Postgres. Audit-chain semantics preserved across instances. | XL |
| 2D | Authoring UI maturation (overlaps Phase 1E). | L |
| 2E | OTA detection-content delivery channel. | M |
| 2F | SOC 2 Type II. | XL+ |

Phase 2C is the largest part of the roadmap. It moves the product from "alpha that runs on a laptop" to "regulated buyer can run this in production." Defer it until at least one design partner has committed to a pilot. A real deployment should inform the schema and operations.

## Pillar 3: Cryptographic audit-grade evidence

Today, a hash-chained NDJSON log lives under `control-plane/store/`. `/v1/verify` walks the chain on demand. Signed CSV and NDJSON exports carry a chain-proof trailer bound to the head hash at export time. This is the alpha. Enterprise compliance teams want more.

### What is missing

- **External timestamping.** Each chain rotation anchors to a public transparency log (Sigstore Rekor). An independent witness confirms the timestamp.
- **Per-record signing.** Distinct from chain hash. Lets a customer share a single record with an auditor without revealing the rest of the log.
- **Selective disclosure via Merkle proofs.** Customer reveals a subset of records and proves the rest exist without showing them.
- **Long-term archival.** Default retention is 90 days. Archive older records to object storage while preserving chain integrity across the rotation boundary and the live log.
- **Forensic export shapes.** "Give me everything for tenant X between dates Y and Z, signed by us, with chain proof and selective Merkle proof, in a format SOC 2 / HIPAA auditors accept." One CLI command.
- **Rule-version provenance.** Every finding cites the exact rule version that produced it. Reproducibility: re-run rule + input on a different machine and get the same finding.
- **Cryptographic per-tenant scoping.** Tenant-A records cannot be decrypted without tenant-A's key. Today, access control provides scoping. Cryptographic scoping should eventually prevent a control-plane operator from reading tenant data without authorization.

### Sequence

| Phase | What | Size |
| --- | --- | --- |
| 3A | Rekor anchoring on chain rotation. | M |
| 3B | Per-record signing + selective Merkle disclosure. | L |
| 3C | Long-term archival to object storage with chain-preserving boundary. | M |
| 3D | Forensic-export CLI. | S |
| 3E | Rule-version provenance baked into findings. | S |
| 3F | Cryptographic per-tenant scoping. | XL |

3D is small and high-leverage. A compliance buyer receives its artifact, so it is worth shipping early.

## How to sequence across pillars

The plan covers twelve months at a solo nights-and-weekends pace. Each quarter should produce a deployable result that a design partner can use.

**Months 1 through 3.** Phase 1A + 1B + 1C: policy CRUD, distribution, hierarchy. Plus Phase 3D: forensic-export CLI. Together, this work supports a design partner conversation about running the product.

**Months 4 through 6.** Phase 2A: RBAC + OIDC. Phase 1D: dry-run / preview. Phase 3A: Rekor anchoring. At the end, a regulated buyer can install Hopframe and configure policies through SSO with role-scoped tokens. The buyer can preview changes before applying them and produce externally witnessed audit evidence.

**Months 7 through 9.** Phase 2B: sensor fleet inventory. Phase 2C kickoff: HA control plane on Postgres. Phase 1E: authoring UI v1. Phase 3E: rule-version provenance. This period ends with a pilot deployment at a design partner.

**Months 10 through 12.** Phase 2C completion. Phase 2E: OTA content delivery. Phase 3B: per-record signing + selective disclosure. Phase 2F kickoff: SOC 2 Type II engagement. This period ends with a paid managed offering ready for a second customer.

This sequence produces a usable product at each quarter boundary. It defers the most expensive pieces (HA migration, SOC 2) until after design-partner validation. This avoids spending a quarter on infrastructure that nobody requested.

## What this roadmap is not

- **Solo scale.** The work happens on nights and weekends. If a design partner does not materialize after Months 1 through 6, slow down, talk to more buyers, or pivot. Do not ship more code.
- **Minimum viable scope.** Each pillar has a minimum viable shape. Phase 2C does not start before Phase 1A is done. Phase 3F does not start before a paying customer asks for it.
- **Three-pillar focus.** Anything that does not move one of the three pillars forward is a distraction in this window. Detection content expansion (which is on the v0.1 gap list) is in scope when it strengthens pillar 1.

## Out of this roadmap

These appear elsewhere on the v0.1 gap list and are not part of the three-pillar core:

- The TypeScript / JavaScript SDK reaches into the Node MCP ecosystem. It is strategic and separable from the three pillars, so it gets its own track.
- Public-corpus benchmarks (HarmBench, JailbreakBench, AgentDojo) provide credibility content and run in parallel.
- The Layer 3 LLM judge runs as an optional detector. This detection capability runs in parallel.
- Trademark and naming work is a one-time task that blocks louder publishing.

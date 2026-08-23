# Security

Hopframe operational security: authentication, authorization, multi-tenancy, TLS, and the integrity guarantees of the audit chain.

## Trust model, in one line

The control plane is the single writer and the verifier. Sensors and SDKs emit events to it; the operator reads from it. Anyone with a valid token reads what their role and tenant allow.

## Authentication

- **Bearer tokens** on `/v1/*` (header or `?token=` for SSE).
- **Local users** for the UI, with hashed passwords, persisted at `HOPFRAME_USERS_PATH` (`users.json`).
- **OIDC SSO** with JWKS verification when `HOPFRAME_OIDC_ISSUER/CLIENT_ID/CLIENT_SECRET/REDIRECT_URL` are all set. Discovery is derived from the issuer.

## Authorization and RBAC

Roles: `viewer`, `editor`, `admin`, `owner`. Tokens bind to a role (`HOPFRAME_ROLE_TOKENS`) and optionally a tenant (`HOPFRAME_TENANT_TOKENS`).

| Role | Can do |
| --- | --- |
| `viewer` | Read events, records, policies, sensors, rules, content, analytics. |
| `editor` | Viewer + create/update/delete policies. |
| `admin` | Editor + users, tokens, audit anchors. |
| `owner` | Everything, including the highest settings. |

Policy list/read and analytics are viewer-readable; mutation is gated to `editor` and up at the handler. Admin surfaces (users, tokens, anchors) require `admin`.

## Multi-tenancy

Tenant-scoped tokens force `event.tenant_id` on writes and filter every read to the bound tenant. The admin token is cross-tenant and can select a tenant via `?tenant_id` on reads.

## Transport security

- The `control-plane` binary accepts `--tls-cert` / `--tls-key` for TLS and `--tls-client-ca` for **mutual TLS**. In practice you typically terminate mTLS at an ingress or sidecar; Hopframe then sits behind it.
- `HOPFRAME_CONTROL_PLANE_ADDR` defaults to `:7090`. Bind to a non-loopback interface only behind a trusted boundary.

## Integrity and signing

- **Audit chain**: SHA-256 hash chain; each record includes the previous head. The chain verifies on start and via `/v1/verify` / `hopframe verify`.
- **Per-record Ed25519 signatures** with Merkle proofs; the UI verifies signatures in-browser via the Web Crypto API.
- **Sigstore Rekor** anchoring: the chain head can be posted to a transparency log on demand; the anchor is written back into the chain.
- **`hopframe-export`**: signs records with the operator key and emits a `VERIFY.md` for offline verification.

Persist the signing seed (`HOPFRAME_SIGNING_KEY`, 64 hex chars) for any deployment that needs verifiable exports. An ephemeral key regenerates every boot.

## Tokens and secrets

- API token secret values are shown once at mint; only the SHA-256 persists. Revoke via `hopframe tokens revoke <id>` or `DELETE /v1/tokens/{id}`.
- OIDC client secret and webhook secrets are read from environment or Helm values.
- Rate limiting on `/v1/*` (reads and writes) protects against abuse; exports are best-effort and never stall ingest on a slow downstream.

## Detection content and OTA

Rule packs are served over `/v1/content/{name}` under a SHA-256 header; sensors compare the manifest version on heartbeat and fetch only changed files. Each rule also hashes its authoritative fields at compile time, so a finding cites the exact rule that produced it.

## Responsible disclosure

Security issues: open a [private security advisory](https://github.com/jLuPSP/hopframe/security/advisories/new). Everything else: [open an issue](https://github.com/jLuPSP/hopframe/issues).

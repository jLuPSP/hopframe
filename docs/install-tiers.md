# Install tiers

Hopframe is one binary set with progressively more knobs turned on. Three tiers cover the realistic deployment shapes; pick the one that matches who you are, then you can graduate later without changing the binary.

| Tier | For | Auth | Audit | Policy plane | OIDC | Rekor | Operational notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Demo | One developer evaluating on a laptop | None | Hash-chained log | Optional | No | No | `make demo` brings up the whole stack on localhost |
| Homelab | A team running it inside their own VPC | Bearer token | Hash-chained log + per-record signing | Recommended | No | No | One Helm install, one config preset, one bearer token |
| Enterprise | Regulated buyers, multi-tenant operators, compliance teams | Bearer + role-bound + OIDC SSO | Hash-chained log + per-record signing + Rekor anchoring + per-tenant scoping | Required | Yes | Yes | All capabilities; expect to also wire mTLS and a real IdP |

Each tier is a superset of the previous one. Nothing has to be reinstalled when you graduate; you flip env vars on the same binary.

## Tier 1: Demo

The point of this tier is to see what Hopframe catches in 30 seconds. It is not for any deployment that ever sees real traffic.

```bash
git clone https://github.com/jLuPSP/hopframe.git
cd hopframe
make demo
```

Open http://127.0.0.1:7090. `make demo` plays the cinematic blind-spot story before the UI is ready. `make run` boots the same stack without narration when you just want to use the product.

What's enabled: inline detection (regex packs + heuristic classifier + behavioral anomaly), the full operator UI (`/`, `/dashboard`, `/policies`, `/sensors`, `/records`, `/rules`, `/audit`, `/settings`), the hash-chained audit log, and signed exports. Nothing is auth-gated.

When to graduate: as soon as a second person needs access, or any traffic that matters touches the sensor.

## Tier 2: Homelab

The point of this tier is to run Hopframe in front of an MCP server in your VPC, with bearer-token auth and per-record signing turned on. It is the right shape for a small team's internal deployment.

Source the preset:

```bash
source examples/config/homelab.env
./bin/control-plane &
./bin/mcp-sensor --config examples/config/mcp-sensor.yaml
```

Or with Helm:

```bash
helm upgrade --install hopframe ./deploy/helm/hopframe \
  --namespace hopframe --create-namespace \
  --set mcpSensor.upstream.url=http://your-mcp-server:8080 \
  --set controlPlane.auth.token=$(openssl rand -hex 32)
```

What's enabled beyond Tier 1:

- `HOPFRAME_API_TOKEN` is required on `/v1/*`. Add it as `Authorization: Bearer $TOKEN` to API and SDK clients.
- `HOPFRAME_SIGNING_KEY` enables per-record Ed25519 signatures on `/v1/records/{seq}` plus signed export bundles via `hopframe-export`.
- `HOPFRAME_RATE_LIMIT_RPS` (optional) caps per-IP requests on `/v1/*`.
- `HOPFRAME_POLICY_PATH` enables operator-authored policies through `/v1/policies` and the `/policies` UI page.
- `HOPFRAME_SENSOR_FLEET=1` enables the fleet inventory at `/v1/sensors` and the `/sensors` UI page.

What stays off in this tier: OIDC, Rekor anchoring, per-tenant scoping. Add them when a second tenant or a compliance auditor enters the picture.

When to graduate: when you have multiple tenants, multiple operators with different roles, or a compliance requirement to externally witness the audit chain.

## Tier 3: Enterprise

The point of this tier is to satisfy a regulated buyer's checklist: SSO, RBAC, multi-tenant isolation, externally witnessed audit. Everything Hopframe ships is on.

To kick the tires locally before standing up real infra:

```bash
make run ENTERPRISE=1
```

This boots the same stack as `make demo` but with auth on, role-bound tokens, persistent signing key, policy plane, sensor fleet, and rate limiting. The script mints fresh tokens on every boot and prints them on stdout. Combine with `UPSTREAM=...` to point at your real MCP at the same time. OIDC and Rekor stay off because they need external infra; see [examples/config/enterprise.env](https://github.com/jLuPSP/hopframe/blob/main/examples/config/enterprise.env) to wire those for real.

For an actual deployment, source the preset:

```bash
source examples/config/enterprise.env
./bin/control-plane
```

What's enabled beyond Tier 2:

- `HOPFRAME_TENANT_TOKENS=token1:tenantA,token2:tenantB` binds bearer tokens to tenants. Reads filter to the bound tenant; writes pin `event.tenant_id` to the bound tenant. A token cannot read or write across boundaries.
- `HOPFRAME_ROLE_TOKENS=token:role,...` binds tokens to roles (`viewer`, `editor`, `admin`, `owner`). The legacy aliases `policy_author`, `tenant_admin`, `super_admin` are still accepted and map to `editor`, `admin`, `owner` respectively.
- `HOPFRAME_OIDC_*` enables SSO. The login flow at `/auth/login` mints a session bearer with a role pulled from the IdP's group claims. The id_token signature is verified against the IdP's JWKS (RS256/384/512, ES256/384) with rotation handling.
- `HOPFRAME_REKOR_URL` anchors chain heads to a Sigstore Rekor instance. Every anchor is also recorded on the chain so the witness becomes part of the trail.
- `HOPFRAME_LLM_JUDGE_URL` enables Layer 3 adjudication on uncertain traffic.
- `HOPFRAME_CONTENT_ROOT` enables OTA detection-content delivery so rule packs ship without binary redeploys.
- mTLS on the sensor link via `--tls-cert`, `--tls-key`, `--tls-client-ca`.

What stays deferred even at this tier (tracked in [roadmap.md](roadmap.md)): HA Postgres-backed control plane, long-term archival to object storage, cryptographic per-tenant scoping, SOC 2 Type II.

## Going from one tier to the next

Hopframe runs the same binary in every tier; the difference is which env vars are set. To move from Tier 2 to Tier 3, source the next preset and restart the control plane. The on-disk audit chain carries forward; sensors reconnect on their next heartbeat.

If you change a token, every consumer needs the new token. If you add OIDC, the legacy `HOPFRAME_API_TOKEN` keeps working as the admin scope; SSO sessions are additive.

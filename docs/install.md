# Install

Hopframe uses one binary set with progressively more features enabled. Three deployment shapes cover the realistic cases. Pick the one that matches you, then move up later without changing the binary. The same binary runs every shape. The env vars determine the shape. Everything Hopframe ships is in this repo under one license. There are no paid tiers or feature gates. "Mode" below describes how much you have configured.

This page covers how much you configure. For where Hopframe sits (the SDK inside your agent, ext_authz on a gateway you already run, the native gateway, or an inline sensor), see [Where it runs](surface-matrix.md).

| Mode | For | Auth | Audit | Policy plane | OIDC | Rekor | Operational notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Demo | One developer evaluating on a laptop | None | Hash-chained log | Optional | No | No | `make demo` brings up the whole stack on localhost |
| Homelab | A team running it inside their own VPC | Bearer token | Hash-chained log + per-record signing | Recommended | No | No | One Helm install, one config preset, one bearer token |
| Secured | Multi-tenant operators and compliance teams | Bearer + role-bound + OIDC SSO | Hash-chained log + per-record signing + Rekor anchoring + per-tenant scoping | Required | Yes | Yes | All capabilities; expect to also wire mTLS and a real IdP |

Each mode is a superset of the previous one. You do not need to reinstall anything when you move up. Change the env vars on the same binary.

## Demo

This mode shows what Hopframe catches in 30 seconds. Do not use it for a deployment that sees real traffic.

```bash
git clone https://github.com/jLuPSP/hopframe.git
cd hopframe
make demo
```

Open http://127.0.0.1:7090. `make demo` plays the blind-spot story before the UI is ready. `make run` boots the same stack without narration when you just want to use the product.

This mode enables inline detection (regex packs + heuristic classifier + behavioral anomaly), the full operator UI (`/`, `/dashboard`, `/policies`, `/sensors`, `/records`, `/rules`, `/audit`, `/settings`), the hash-chained audit log, and signed exports. Nothing is auth-gated.

Move up as soon as a second person needs access or any traffic that matters touches the sensor.

## Homelab

This mode runs Hopframe in front of an MCP server in your VPC with bearer-token auth and per-record signing enabled. It fits a small team's internal deployment.

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

This mode adds these features to Demo:

- `HOPFRAME_API_TOKEN` is required on `/v1/*`. Add it as `Authorization: Bearer $TOKEN` to API and SDK clients.
- `HOPFRAME_SIGNING_KEY` enables per-record Ed25519 signatures on `/v1/records/{seq}` plus signed export bundles via `hopframe-export`.
- `HOPFRAME_RATE_LIMIT_RPS` (optional) caps per-IP requests on `/v1/*`.
- `HOPFRAME_POLICY_PATH` enables operator-authored policies through `/v1/policies` and the `/policies` UI page.
- `HOPFRAME_SENSOR_FLEET=1` enables the fleet inventory at `/v1/sensors` and the `/sensors` UI page.

OIDC, Rekor anchoring, and per-tenant scoping stay off in this mode. Add them when a second tenant or a compliance auditor enters the picture.

Move up when you have multiple tenants, multiple operators with different roles, or a compliance requirement to externally witness the audit chain.

## Secured

This mode enables SSO, RBAC, multi-tenant isolation, and an externally witnessed audit for a regulated buyer's checklist. Everything Hopframe ships is on.

To kick the tires locally before standing up real infra:

```bash
make run SECURE=1
```

This boots the same stack as `make demo` with auth, role-bound tokens, a persistent signing key, the policy plane, the sensor fleet, and rate limiting enabled. The script mints fresh tokens on every boot and prints them on stdout. Combine it with `UPSTREAM=...` to point at your real MCP at the same time. OIDC and Rekor stay off because they need external infrastructure. See [examples/config/secured.env](https://github.com/jLuPSP/hopframe/blob/main/examples/config/secured.env) to wire them for a deployment.

For an actual deployment, source the preset:

```bash
source examples/config/secured.env
./bin/control-plane
```

This mode adds these features to Homelab:

- `HOPFRAME_TENANT_TOKENS=token1:tenantA,token2:tenantB` binds bearer tokens to tenants. Reads filter to the bound tenant; writes pin `event.tenant_id` to the bound tenant. A token cannot read or write across boundaries.
- `HOPFRAME_ROLE_TOKENS=token:role,...` binds tokens to roles (`viewer`, `editor`, `admin`, `owner`). The legacy aliases `policy_author`, `tenant_admin`, `super_admin` are still accepted and map to `editor`, `admin`, `owner` respectively.
- `HOPFRAME_OIDC_*` enables SSO. The login flow at `/auth/login` mints a session bearer with a role pulled from the IdP's group claims. The id_token signature is verified against the IdP's JWKS (RS256/384/512, ES256/384) with rotation handling.
- `HOPFRAME_REKOR_URL` anchors chain heads to a Sigstore Rekor instance. Every anchor is also recorded on the chain so the witness becomes part of the trail.
- `HOPFRAME_LLM_JUDGE_URL` enables Layer 3 adjudication on uncertain traffic.
- `HOPFRAME_CONTENT_ROOT` enables OTA detection-content delivery so rule packs ship without binary redeploys.
- mTLS on the sensor link via `--tls-cert`, `--tls-key`, `--tls-client-ca`.

The following work stays deferred even in this mode (tracked in [roadmap.md](roadmap.md)): HA Postgres-backed control plane, long-term archival to object storage, cryptographic per-tenant scoping, SOC 2 Type II.

## Moving up

Hopframe runs the same binary in every mode. The env vars determine the mode. To move from Homelab to Secured, source the next preset and restart the control plane. The on-disk audit chain carries forward. Sensors reconnect on their next heartbeat.

If you change a token, every consumer needs the new token. If you add OIDC, the legacy `HOPFRAME_API_TOKEN` keeps working as the admin scope. SSO sessions are additive.

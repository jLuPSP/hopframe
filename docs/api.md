# HTTP API reference

The control plane exposes everything over HTTP. The web UI and the `hopframe` CLI are thin wrappers over this same surface.

## Base URL and auth

- Base: the control plane address (default `http://127.0.0.1:7090`).
- Auth: a bearer token via `Authorization: Bearer <token>` **or** a `?token=` query parameter (SSE clients must use the query form).
- When no token is configured, `/v1/*` runs unauthenticated in admin scope. With auth configured, `viewer` can read, mutations require `editor` or above, admin operations `admin`.
- Tenant-scoped tokens force `event.tenant_id`; the admin token can pass `?tenant_id=` to pick a tenant.

Unauthenticated or open: `/healthz` (liveness), `/metrics` (Prometheus), `/`, `/auth/*` (the UI and its session).

## Events

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/v1/events` | Sensor event ingest (one event per body). |
| GET | `/v1/events` | Query recent events with filters (`action`, `severity`, `category`, `method`, `limit`). |
| GET | `/v1/events/stream` | Server-sent events live stream. |
| GET | `/v1/events.ndjson` | NDJSON export. |
| GET | `/v1/events.csv` | CSV export. |

## Records and integrity

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/stats` | Chain head, seq, backing store. |
| GET | `/v1/verify` | Re-walk the chain end to end; reports the first mismatch or a clean chain. |
| GET | `/v1/records/{seq}` | A record with its canonical bytes, Ed25519 signature, and Merkle proof. |
| POST | `/v1/audit/anchor` | Trigger a Sigstore Rekor anchor of the chain head (admin). |
| GET | `/v1/agent-runs/{id}/timeline` | Every cached record for one agent run, ascending. |

## Analytics

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/analytics/tools` | Tool risk ranking. |
| GET | `/v1/analytics/agents` | Agent activity. |
| GET | `/v1/analytics/categories` | Finding category mix. |
| GET | `/v1/analytics/counterparties` | Counterparty risk. |
| GET | `/v1/analytics/tasks` | A2A task concerns. |
| GET | `/v1/metrics` | Time-series metric points. |
| GET | `/v1/histogram` | Latency histogram. |

## Policies

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/policies` | List policies (viewer). |
| POST | `/v1/policies` | Create (editor). |
| GET | `/v1/policies/{id}` | Fetch one (viewer). |
| PATCH | `/v1/policies/{id}` | Update (editor). |
| DELETE | `/v1/policies/{id}` | Delete (editor). |
| GET | `/v1/policies/{id}/preview` | Dry-run against the last 1000 events (viewer). |

Policy mutations are appended to the audit chain.

## Sensors, taint, content, rules

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/sensors` | Fleet inventory (viewer). |
| GET | `/v1/sensors/heartbeat` | Sensor heartbeat (register + report applied policy version). |
| GET | `/v1/taints` | Shared taint registry (fingerprints, never raw values). |
| GET | `/v1/taints/match` | Match outgoing values against a run's taints. |
| GET | `/v1/content/manifest` | OTA content manifest (viewer). |
| GET | `/v1/content/{name}` | Fetch a rule pack under a SHA-256 header (viewer). |
| GET | `/v1/rules` | Browse loaded rule packs (viewer). |

## Users, tokens, auth

| Method | Path | Purpose |
| --- | --- | --- |
| GET/POST | `/v1/users` | List / add users (admin). |
| GET | `/v1/users/{name}` | Fetch, and PATCH password / role (admin). |
| GET/POST | `/v1/tokens` | List / mint API tokens (admin). |
| DELETE | `/v1/tokens/{id}` | Revoke (admin). |
| POST | `/auth/login` | Password login (form). |
| POST | `/auth/logout` | End the UI session. |
| GET | `/auth/session` | Current session info. |
| GET | `/auth/oidc/login` | Start OIDC SSO. |
| GET | `/auth/oidc/callback` | OIDC callback. |

Token secret values are shown once at mint; only the SHA-256 persists.

## Status and metrics

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/healthz` | Liveness. |
| GET | `/metrics` | Prometheus metrics (request counts, latency, rate-limited counters). |

## Rate limiting

A per-IP token-bucket limiter applies to `/v1/*` writes when configured (`HOPFRAME_RATE_LIMIT_RPS`). Exceeded requests return `429` with `Retry-After: 1`. `/healthz`, `/metrics`, and the UI are unconstrained.

The full endpoint list lives in [`control-plane/api/api.go`](https://github.com/jLuPSP/hopframe/blob/main/control-plane/api/api.go).
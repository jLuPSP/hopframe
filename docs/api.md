# HTTP API reference

Hopframe is API-first. The UI and the CLI ([docs/cli.md](cli.md)) are thin clients over the same `/v1/*` endpoints. SDKs ([Python](https://github.com/jLuPSP/hopframe/tree/main/sdk/python), [TypeScript](https://github.com/jLuPSP/hopframe/tree/main/sdk/typescript)) only emit events to the ingest endpoint.

## Conventions

- **Base URL.** `http://your-control-plane:7090` for demo or homelab mode. The `--tls-cert` + `--tls-key` flags on the control-plane binary enable HTTPS.
- **Auth.** Send a bearer token in the `Authorization` header, the same value in a `?token=` query param (for SSE clients that cannot set headers), or a `hopframe_session` cookie set by `/auth/login`. With no auth configured (no-auth demo), the API is open.
- **Content type.** Requests with bodies must send `Content-Type: application/json`. Responses are JSON except exports: `/v1/events.csv` returns CSV, `/v1/events.ndjson` returns NDJSON.
- **Errors.** The API returns plain text on `4xx`/`5xx` for now (the body is the error message). A future v2 will normalize to `{"error": "...", "code": "..."}`; status codes will not change, so rely on them.
- **Pagination.** List endpoints accept `?limit=N` (default 50, max 10000) and `?since_seq=N`.
- **Rate limiting.** When `HOPFRAME_RATE_LIMIT_RPS` is set, `/v1/*` enforces a per-IP token bucket. Rejections return `429 Too Many Requests` with `Retry-After: 1`.

## Roles

Every authenticated request resolves to a role. List endpoints typically require `viewer`; mutations require `editor` or higher.

| Role | What it can do |
| --- | --- |
| `viewer` | Read every list and get endpoint within the bound tenant scope. |
| `editor` | + Create, update, delete policies. Same tenant scope. |
| `admin` | + Manage sensors, content, users (within tenant), API tokens. |
| `owner` | Cross-tenant. Can mint admins and owners. The legacy `HOPFRAME_API_TOKEN` is implicitly this role. |

## Health and meta

### `GET /healthz`

Component-level health. Returns 200 when every component is healthy, 503 on any failure. No auth.

```json
{
  "status": "ok",
  "checked_at": "2026-04-27T02:50:00Z",
  "checks": {
    "chain": {"ok": true},
    "store": {"ok": true},
    "policies": {"ok": true},
    "chain_head_seq": 31,
    "policy_version": 5
  }
}
```

### `GET /metrics`

Prometheus text exposition format. No auth. See [Operations](operations.md#metrics) for the full counter list.

### `GET /v1/stats`

Chain head and store path. Used by integrity badges and dashboards.

```json
{ "seq": 31, "head_hash": "abc...", "path": "data/events.ndjson" }
```

### `GET /v1/verify`

Re-walk the on-disk chain and report integrity. Returns `{"ok": true}` on success, or `{"ok": false, "error": "...", "bad_seq": N}` on tamper detection. Used by the integrity badge and `hopframe verify`.

## Events (the audit chain)

### `POST /v1/events`

Sensor ingest. Body is a single Hopframe event. Returns the assigned sequence and chain hash. Tenant-scoped tokens force `event.tenant_id` to the bound tenant on write.

```bash
curl -X POST http://127.0.0.1:7090/v1/events \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @event.json
```

Response: `202 Accepted` with `{"seq": 32, "hash": "abc..."}`.

### `GET /v1/events`

Query recent events. All filters are optional and AND together.

| Param | Meaning |
| --- | --- |
| `limit` | Max records (default 50, max 10000) |
| `since_seq` | Return only records with seq > N |
| `action` | `allow` / `warn` / `block` |
| `severity` | Exact match: `info` / `low` / `medium` / `high` / `critical` |
| `min_severity` | Minimum severity (inclusive) |
| `method` | JSON-RPC method (e.g. `tools/list`) |
| `category` | Finding category (e.g. `prompt-injection`) |
| `search` | Substring match in the raw message body |
| `tenant_id` | Tenant filter (admin scope only; tenant-scoped tokens force their bound tenant) |

```json
{ "records": [ { "seq": 31, "ingest_at": "...", "prev_hash": "...", "hash": "...", "event": { ... } } ] }
```

### `GET /v1/events/stream`

Server-Sent Events live stream. `?backlog=N` returns the most recent N records before the live tail starts. The browser cannot set headers on `EventSource`; use `?token=` for auth.

### `GET /v1/events.csv` / `GET /v1/events.ndjson`

The same filters as `GET /v1/events` produce a downloadable file with a chain-proof trailer. The trailer binds the export to a specific chain head, so an auditor can verify the file was not altered after it left your control plane. Headers `X-Hopframe-Chain-Head` / `X-Hopframe-Exported-At` / `X-Hopframe-Record-Count` mirror the trailer fields.

### `GET /v1/records/{seq}`

The per-record inspector returns the canonical bytes, the per-record Ed25519 signature (when a signing key is configured), and a Merkle proof tying the record to a snapshot of recent records. The UI's `/records` page verifies the signature in the browser.

```json
{
  "record": { ... },
  "canonical": "{\"seq\":31, ...}",
  "signature": "base64...",
  "public_key": "hex...",
  "merkle_root": "hex...",
  "merkle_proof": [ {"sibling": "hex...", "right_sibling": true} ],
  "merkle_window": 100
}
```

### `GET /v1/agent-runs/{id}/timeline`

Forensic replay. Returns every cached event for the given `agent_run_id` in ascending sequence order, reconstructing one agent's session across MCP and A2A.

## Policies

`viewer` can read; `editor` can write.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/policies` | List policies (all, or scoped by token's tenant) |
| `POST` | `/v1/policies` | Create a new policy |
| `GET` | `/v1/policies/active` | The enabled subset, what sensors fetch on heartbeat |
| `GET` | `/v1/policies/{id}` | Get one policy |
| `PATCH` | `/v1/policies/{id}` | Update fields. Bumps version, audits the change |
| `DELETE` | `/v1/policies/{id}` | Remove |
| `POST` | `/v1/policies/{id}/preview` | Dry-run against recent events |

A policy body:

```json
{
  "name": "block-tool-poisoning-on-acme",
  "description": "Stricter posture for the production github surface.",
  "enabled": true,
  "scope": {"tenant_id": "acme", "server_name": "github-mcp"},
  "selector": {"categories": ["tool-poisoning"], "min_severity": "high"},
  "disposition": {"mode": "block"}
}
```

Resolution selects the most-specific scope (server > sensor > tenant > org default); within ties, the strongest mode wins. See [Policies](policies.md) for the full semantics.

## Sensors

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/sensors` | Fleet inventory with stale + drift markers |
| `POST` | `/v1/sensors/heartbeat` | Sensor heartbeat (sensor calls this every 30s) |

Heartbeat body:

```json
{
  "sensor_id": "edge-1",
  "tenant_id": "acme",
  "hostname": "kube",
  "binary_version": "0.1.0",
  "policy_version": 5,
  "content_version": "abc123"
}
```

Heartbeat ack:

```json
{ "ack": true, "policy_version": 6, "content_version": "abc124" }
```

A version mismatch is the sensor's signal to refetch. The control plane never pushes; the sensor polls.

## Detection content

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/rules` | The loaded rule pack as JSON, with category counts |
| `GET` | `/v1/content/manifest` | OTA content manifest: file list, hashes, version |
| `GET` | `/v1/content/{name}` | Fetch one rule pack file |

The manifest version is a SHA-256 fold of every file's hash. The sensor compares its applied version on heartbeat and refetches changed files.

## Audit

| Method | Path | Purpose | Role |
| --- | --- | --- | --- |
| `GET` | `/v1/verify` | Re-walk the chain | viewer |
| `POST` | `/v1/audit/anchor` | Anchor the current chain head to Sigstore Rekor | admin |

Anchor response:

```json
{
  "head_hash": "...",
  "anchored_at": "...",
  "log_index": 99342,
  "uuid": "24296fb24b8ad77a",
  "url": "https://rekor.sigstore.dev/api/v1/log/entries/24296fb24b8ad77a",
  "integrated_at": "..."
}
```

## Users and tokens

| Method | Path | Purpose | Role |
| --- | --- | --- | --- |
| `GET` | `/v1/users` | List | admin |
| `POST` | `/v1/users` | Create | admin (owner to mint owners) |
| `GET` | `/v1/users/{name}` | Get one | admin or self |
| `PATCH` | `/v1/users/{name}` | Update role/tenant | owner |
| `DELETE` | `/v1/users/{name}` | Delete | owner |
| `POST` | `/v1/users/{name}/password` | Rotate password | self or owner |
| `GET` | `/v1/tokens` | List API tokens | admin |
| `POST` | `/v1/tokens` | Mint a new token (returns secret once) | admin |
| `DELETE` | `/v1/tokens/{id}` | Revoke | admin |

Token mint response (the secret appears only here):

```json
{
  "id": "tok_a3f9b1",
  "name": "ci-pipeline",
  "role": "editor",
  "tenant_id": "acme",
  "created_at": "...",
  "secret": "hf_<base64>"
}
```

Subsequent reads omit `secret`.

## Auth flow

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/auth/login` | Username + password login. Sets `hopframe_session` cookie. |
| `POST` | `/auth/logout` | Revoke the current session. |
| `GET` | `/auth/session` | Current caller's identity. Returns `{"role": "anonymous"}` in the no-auth mode. |
| `GET` | `/auth/oidc/login` | Begin OIDC auth-code flow (when configured). |
| `GET` | `/auth/oidc/callback` | OIDC callback. |

## Analytics

These power the `/dashboard` page. All return `{"<resource>": [...]}` shapes.

| Path | Returns |
| --- | --- |
| `GET /v1/analytics/categories` | `[{"category": "...", "count": N}]` |
| `GET /v1/analytics/counterparties?limit=N` | Per-peer risk score with severity weighting and time decay |
| `GET /v1/analytics/tools?limit=N` | Per-tool call counts and finding rates |
| `GET /v1/analytics/agents?limit=N` | Per-agent-run activity |
| `GET /v1/analytics/tasks?limit=N` | A2A task concerns |
| `GET /v1/metrics?window=5m&bucket=10s` | Rolling window metrics + sparkline |
| `GET /v1/histogram?window=5m&bucket=10s` | Per-bucket allow/warn/block counts |

## Error responses

Common codes:

| Status | When |
| --- | --- |
| 400 | Malformed body, missing required field, invalid role |
| 401 | Auth configured but no valid token / session |
| 403 | Auth valid but role insufficient |
| 404 | Resource not found, or feature not enabled (e.g. `/v1/users` when no user store) |
| 409 | Constraint violation (duplicate username, etc.) |
| 429 | Rate limit exceeded; honor `Retry-After` |
| 500 | Server error. Check the control-plane log. |
| 503 | One or more `/healthz` checks failed |

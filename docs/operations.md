# Operations

What an operator needs to know to run Hopframe in real life. Persistence and backup, capacity, healthz semantics, what every metric means, what to do when each component is unhappy.

## Persistence

### Backend choice: file vs Postgres

The control plane has two interchangeable audit-chain backends:

| Backend | When to pick | DSN |
| --- | --- | --- |
| **File** (default) | Single-instance deployments. Homelab, design-partner pilots, anywhere the control plane runs as one process. ~10k events/sec ceiling on commodity NVMe. No external dependency. | (default; set `--log` or `HOPFRAME_CONTROL_PLANE_LOG`) |
| **Postgres** | Multi-instance prep, managed-DB compliance, anywhere a regulated buyer requires the audit log to live in a database they back up the same way as everything else. Compatible with [Cloud SQL](https://cloud.google.com/sql/docs/postgres), [AWS RDS for PostgreSQL](https://aws.amazon.com/rds/postgresql/), [Azure Database for PostgreSQL](https://learn.microsoft.com/en-us/azure/postgresql/), Aiven, Neon, Supabase, and self-hosted Postgres 14+. | `HOPFRAME_STORE_DSN=postgres://user:pass@host:5432/dbname?sslmode=require` |

Pick the backend at boot via `HOPFRAME_STORE_DSN` (or `--store-dsn`):

- **Empty / unset / file path:** file backend. `--log` controls the path.
- **`postgres://...` or `postgresql://...`:** Postgres backend. Schema is created idempotently on first connect; no migration tool required.

The hash-chain semantics (per-record SHA-256 over canonical bytes, prev-hash linking, Verify re-walks end-to-end) are identical in both backends. Per-record Ed25519 signatures, Merkle proofs, and Sigstore Rekor anchoring all work the same way.

For Postgres, append linearizability is guaranteed via a `SELECT ... FOR UPDATE` row lock on the singleton chain-head row inside the append transaction; concurrent appenders serialize on the lock without serialization-failure retry loops. Use `sslmode=require` (or `verify-full` in production) for any non-localhost deployment.

### Files on disk

The control plane writes up to five artifacts to disk (which ones appear depends on the env vars you set; the events log is replaced by Postgres when `HOPFRAME_STORE_DSN` is set):

| File | What | If it disappears |
| --- | --- | --- |
| `data/events.ndjson` | Append-only audit chain. Every event ever ingested. | Chain is gone. Existing signed exports stop verifying because the chain head they reference is no longer reachable. |
| `data/policies.json` | Policy resource state. | Policies are gone. Sensors fall back to rule-default modes on next heartbeat. |
| `data/users.json` | Local user accounts (when `HOPFRAME_USERS_PATH` is set). | Logins fail until you bootstrap a new admin via `HOPFRAME_BOOTSTRAP_ADMIN` on the next start. |
| `data/tokens.json` | API token store (when `HOPFRAME_TOKENS_PATH` is set). | All API tokens minted via the API are revoked. Env-bound tokens (`HOPFRAME_API_TOKEN`, `HOPFRAME_TENANT_TOKENS`, `HOPFRAME_ROLE_TOKENS`) keep working. |
| `data/signing.seed` | Ed25519 seed for per-record signatures. | Newly signed records use a fresh key, breaking verification of any previously exported bundle that referenced the old public key. |

The audit chain is the load-bearing artifact. Treat it like a database.

## Backup

The chain is append-only NDJSON; backup is a file copy. Full nightly + incremental hourly is sufficient for most deployments.

```bash
# nightly (run from cron / systemd timer)
TS=$(date -u +%Y%m%dT%H%M%S)
tar czf "/backup/hopframe-$TS.tar.gz" \
  --transform "s|^|hopframe-$TS/|" \
  /var/lib/hopframe/events.ndjson \
  /var/lib/hopframe/policies.json \
  /var/lib/hopframe/users.json \
  /var/lib/hopframe/tokens.json \
  /var/lib/hopframe/signing.seed
```

Restore is a file copy in the other direction; the binary picks up the existing chain at boot via the `events.ndjson.genesis` sidecar.

For higher durability, set `HOPFRAME_REKOR_URL` to point chain-head anchors at a Sigstore Rekor instance (public sigstore.dev or your own). The witnessed log index gives a third-party-verifiable timestamp for every anchor, which is harder to lose than a backup.

## Healthz semantics

`GET /healthz` returns 200 only when every component reports OK. 503 on any failure. The body lists every check.

| Check | What it means |
| --- | --- |
| `chain` | The on-disk hash chain re-walks cleanly. Cached for 30 seconds; full corruption surfaces within 30s of `Verify()` running. |
| `store` | The append-only log file is reachable for stat. |
| `policies` | Policy store is loaded and queryable. |
| `content` | Detection-content directory is loaded. |
| `users` | User store is loaded. |
| `tokens` | Token store is loaded. |
| `chain_head_seq` | Numeric: the current sequence at the head of the chain. Useful for spot-checking liveness. |
| `policy_version` | Numeric: monotonic version that increments on every policy change. |
| `content_version` | String: SHA-256 fold of the content manifest. |
| `user_count` | Numeric. |

A load balancer should treat 200 as "route traffic to this instance" and any non-200 as "drain me." A human operator should treat a non-200 as a paging condition and look at which component is degraded in the body.

## Metrics

`GET /metrics` returns Prometheus text-format counters and gauges. Hand-rolled to avoid pulling `prometheus/client_golang`.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `hopframe_uptime_seconds` | gauge | | Time since the control plane started. |
| `hopframe_chain_head_seq` | gauge | | Sequence of the most recent chain record. |
| `hopframe_events_ingested_total` | counter | `action`, `severity` | Sensor-emitted events received via `/v1/events`. |
| `hopframe_http_requests_total` | counter | `method`, `path`, `status` | HTTP requests served. Path labels are folded so cardinality stays bounded. |
| `hopframe_rate_limited_total` | counter | `path` | Requests rejected by the per-IP rate limiter. |
| `hopframe_policy_changes_total` | counter | `op`, `tenant` | CRUD operations on policies. `op` is `create`, `update`, or `delete`. |

Scrape interval: 10-30s is plenty.

## Capacity

Numbers from a laptop benchmark; treat as a floor, not a ceiling.

- **Detection pipeline:** 115k evals/sec, p99 ~ 160µs. Single inline sensor, no LLM judge. Adding the Layer 3 LLM judge moves the latency floor of the affected events to whatever the model returns (typically 300-1500ms). The judge is opt-in and only runs on the uncertain band.
- **Audit chain append:** SHA-256 + JSON marshal + fsync per record. Roughly 5-15k records/sec on commodity NVMe. The fsync is the critical-path cost.
- **In-memory cache:** the control plane keeps the last 1024 records hot for the UI and analytics. Bump `CacheCap` in the store options if your deployment runs higher-volume queries.
- **Single-instance ceiling:** Hopframe v0.1 is single-process. Plan for one control-plane per cluster or environment. The Phase 2C HA migration in [roadmap.md](roadmap.md) moves persistence to Postgres so the control plane can run multi-instance behind a load balancer.

For a homelab deployment serving 5-10 sensors and a handful of operators, a single 2-vCPU 4-GB-RAM container is overprovisioned. For a larger fleet (50+ sensors, sustained 10k+ events/sec), watch `hopframe_chain_head_seq` rate and disk IOPS; you will hit fsync throughput before you hit CPU.

## Failure modes

| What you see | What it means | What to do |
| --- | --- | --- |
| `/healthz` chain check failed | Chain integrity broken. Either tampering or a half-written record after a crash. | Don't trust subsequent records until investigated. Pull the most recent backup and diff. The bad seq is in the response body. |
| `/v1/sensors` shows `policy_drift: true` past one heartbeat | Sensor cannot reach the control plane, or its bearer token is wrong, or it crashed during refetch. | Check the sensor's logs for "policy refetch" errors. Validate `HOPFRAME_CONTROL_PLANE_URL` and `HOPFRAME_API_TOKEN`. |
| `/v1/sensors` shows `content_drift: true` past one heartbeat | Same as policy drift, for OTA content delivery. | Same diagnosis. The sensor is operating with a stale rule pack until resolved. |
| `dropped > 0` counter on the sensor's spool | The control plane was unreachable; the sensor buffered events; the spool filled before the link came back. | Increase `emitter.spool_max_bytes` in the sensor config, or fix the control-plane outage. |
| Webhook exporter delivery failures | SIEM target is unreachable or rejecting the HMAC. | The exporter does not retry by default. Use Splunk HEC for retry semantics, or scrape `/v1/events.ndjson` from the SIEM on a schedule. |
| `429 Too Many Requests` on `/v1/*` | The configured rate limit (`HOPFRAME_RATE_LIMIT_RPS`) is being hit. | Either raise the limit, or fix the client that is bursting. |
| `503` from `/healthz` | One component degraded. The body says which. | Read the body. Common: chain integrity broken (load backup); store unreachable (check disk). |

## Upgrade

The control plane is a single binary. Upgrade by:

1. Stop the current process.
2. Replace the binary.
3. Start.

The audit chain carries forward. Sensors reconnect on their next heartbeat. Schema-version bumps to the event envelope are documented in [CHANGELOG.md](https://github.com/jLuPSP/hopframe/blob/main/CHANGELOG.md); the codebase tolerates unknown fields, so a v1 control plane reading v2 events from a newer sensor will not crash.

## Disaster recovery

If you lose the control-plane host entirely:

1. Restore the latest `data/` backup to the new host.
2. Boot the binary with the same env (`HOPFRAME_API_TOKEN`, etc.).
3. Sensors reconnect on their next heartbeat with no state lost.

The audit chain genesis sidecar (`events.ndjson.genesis`) carries the chain start hash across the rotation boundary. Loss of this file with the chain still present makes integrity verification impossible; back up the genesis file alongside the chain.

For multi-region or cross-region failover at v0.1: the only supported path is active-passive with the passive instance restored from backup. Phase 2C in [roadmap.md](roadmap.md) tracks the active-active HA work.

## TLS and mTLS

The control plane terminates TLS when `--tls-cert` and `--tls-key` are set. Adding `--tls-client-ca` enforces mutual TLS, requiring sensors to present a client certificate from the named CA bundle.

For homelab use on a private VPC, plain HTTP is acceptable. For anything internet-facing or carrying tenant traffic, terminate TLS at the control plane or at the ingress in front of it.

## Mounting on Kubernetes

The Helm chart at `deploy/helm/hopframe/` deploys the control plane with a PVC for `/var/lib/hopframe`, a configurable retention, and the bearer-token / per-tenant / role-token env vars surfaced in `values.yaml`. See the chart's README for the full set of values.

```bash
helm upgrade --install hopframe ./deploy/helm/hopframe \
  --namespace hopframe --create-namespace \
  --set mcpSensor.upstream.url=http://your-mcp-server:8080 \
  --set controlPlane.persistence.size=20Gi
```

## Sensor side

Sensors are stateless except for the durable spool. If a sensor pod dies and a new one starts:

- Heartbeat resumes within 30s; the fleet view shows the old pod as stale and the new one as fresh.
- The spool on the old volume is lost unless you mount it across pod restarts. For at-least-once delivery, give the sensor a small PVC for `data/mcp-spool/`.

Sensor config lives in YAML loaded at boot. To change the upstream URL or the rule directories, restart the sensor; policy and content updates flow over the heartbeat path and do not need a restart.

## Where to look in the code

| Question | Path |
| --- | --- |
| How does ingest work? | `control-plane/api/api.go::ingest` |
| What does `Verify()` actually do? | `control-plane/store/store.go::Verify` |
| How does the spool replay? | `internal/emitter/spool.go` |
| How is the per-record signature computed? | `pkg/audit/sign.go::CanonicalRecord` + `Signer.Sign` |
| What does a Rekor anchor look like on the wire? | `pkg/audit/rekor.go::buildHashedRekord` |

See [Developer guide](developer.md) for the rest.

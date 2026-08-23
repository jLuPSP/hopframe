# Operations

How to run Hopframe in front of real traffic: storage, retention, observability, exporters, high availability, and honest notes on what is built.

## Storage and the audit chain

- **Default**: a file-backed append-only NDJSON log. The chain is a SHA-256 hash chain with per-record Ed25519 signatures and Merkle proofs. See [How it works](how-it-works.md#the-audit-chain-and-the-evidence).
- **Postgres**: set `HOPFRAME_STORE_DSN` (or the `--store-dsn` flag) to a `postgres://...` DSN. Compatible with managed Postgres (Cloud SQL, AWS RDS, Azure Database for PostgreSQL, Aiven, Neon, Supabase) and self-hosted Postgres 14+. The bundled `docker compose --profile postgres` image is for local testing.
- **Rotation**: records older than the retention window are dropped; the surviving prefix keeps its hash chain, and the chain-start anchor is updated. Run via a background ticker (`--rotate-every`, default 1h).

**Backup**: back up the NDJSON log file (or the Postgres database) and the `HOPFRAME_SIGNING_KEY`. The chain and signatures are what let you prove an untouched history, so back them up together.

## Observability

- **Prometheus**: `/metrics` on the control plane exposes request counts, latency, and rate-limited counters.
- **Live events**: the `GET /v1/events/stream` SSE stream and the `/v1/events.ndjson` / `/v1/events.csv` exports.
- **Integrity**: `hopframe verify` re-walks the chain; `/v1/verify` does the same over HTTP.
- **Web UI**: `/` on the control plane: event stream, dashboards, policies, sensors, the record/signature inspector, and the rule browser.

## Exporters

| Sink | Config |
| --- | --- |
| Generic webhook | `HOPFRAME_WEBHOOK_URL` + `HOPFRAME_WEBHOOK_SECRET` + optional `HOPFRAME_WEBHOOK_MIN_SEVERITY`. |
| Splunk HEC | `HOPFRAME_SPLUNK_URL`. |

Exporters are best-effort: errors log to the hub drop counter and a slow exporter does not stall ingest.

## The hopframe-export bundle

````bash
hopframe export --output audit-bundle
````

Pulls a window of records, signs each with the operator key, builds a Merkle root, and writes a manifest plus a `VERIFY.md`. The receiver verifies offline without contacting the control plane. This is the shape a compliance auditor can follow.

## High availability

- **Control plane**: the Helm chart defaults to a single replica on a `StatefulSet` with a PVC. A Postgres backend (shared) is the path to multi-replica for the audit chain; the file backend is single-writer by design.
- **Sensors**: stateless proxies; scale horizontally. Cross-replica taint uses the `Remote` backend (fingerprints only, never raw values) to close the split-sensor gap.
- **Retention and rotation**: stop-the-world for the file backend; a Postgres backend makes it a SQL delete.

See the chart's [README](https://github.com/jLuPSP/hopframe/tree/main/deploy/helm/hopframe) for the deployment picture.

## Health and readiness

`GET /healthz` is the liveness check. Wire it into your orchestrator. Prometheus `/metrics` gives readiness signals the webhook exporters do not.

## What is not built

- Multi-replica HA for the file-backed audit chain (use Postgres).
- Automatic certificate rotation for TLS (terminate mTLS at your ingress/gateway today).
- A SaaS control plane.
- Profiling / tracing end-to-end beyond the per-message `latency_micros` field and Prometheus counters.

These are honest boundaries, not growth promises. If one is blocking you, open an issue.

## Upgrades

1. Back up the log (or database) and signing key.
2. Read the [CHANGELOG](https://github.com/jLuPSP/hopframe/blob/main/CHANGELOG.md) for the target version.
3. Update the image tag / binary. The chain verifies on start; a tampered or incompatible log fails fast rather than silently.
4. Run `hopframe verify` and spot-check the chain head in the UI.

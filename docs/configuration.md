# Configuration reference

Hopframe is configured three ways, all surfacing the same knobs: environment variables (control plane), a YAML file (sensor), and Helm chart values (Kubernetes).

## Control plane: environment variables

| Variable | Default | What it sets |
| --- | --- | --- |
| `HOPFRAME_CONTROL_PLANE_ADDR` | `:7090` | Listen address. |
| `HOPFRAME_CONTROL_PLANE_LOG` | `data/events.ndjson` | File path for the append-only audit log. |
| `HOPFRAME_STORE_DSN` | (unset) | Postgres DSN for the audit chain. Empty uses the file backend. |
| `HOPFRAME_CONTROL_PLANE_RETENTION` | `2160h` (90d) | Drop records older than this on rotation. |
| `HOPFRAME_API_TOKEN` | (unset) | Admin (cross-tenant) bearer token. |
| `HOPFRAME_TENANT_TOKENS` | (unset) | Comma-separated `token:tenant` pairs. |
| `HOPFRAME_ROLE_TOKENS` | (unset) | Comma-separated `token:role` pairs. |
| `HOPFRAME_SIGNING_KEY` | (in-memory) | Path to the persistent Ed25519 signing seed (64 hex chars). |
| `HOPFRAME_REKOR_URL` | (unset) | Sigstore Rekor endpoint for chain-head anchors. |
| `HOPFRAME_REKOR_DISABLED` | (unset) | `1` runs the code path without outbound calls. |
| `HOPFRAME_POLICY_PATH` | (unset) | Path to persist policies. |
| `HOPFRAME_SENSOR_FLEET` | (unset) | Enable the sensor fleet inventory. |
| `HOPFRAME_CONTENT_ROOT` | (unset) | Root of OTA detection-content packs. |
| `HOPFRAME_RATE_LIMIT_RPS` | (unset) | Per-IP rate limit on every `/v1/*` request, reads and writes. `0` disables. |
| `HOPFRAME_USERS_PATH` | (unset) | JSON file of hashed users. |
| `HOPFRAME_BOOTSTRAP_ADMIN` | (unset) | `username:password` seeded on first start. |
| `HOPFRAME_WEBHOOK_URL` | (unset) | SIEM webhook URL. |
| `HOPFRAME_WEBHOOK_SECRET` | (unset) | Webhook HMAC secret. |
| `HOPFRAME_WEBHOOK_MIN_SEVERITY` | (unset) | Minimum severity to export. |
| `HOPFRAME_SPLUNK_URL` | (unset) | Splunk HEC endpoint. |
| `HOPFRAME_SPLUNK_TOKEN` | (unset) | Splunk HEC token. |
| `HOPFRAME_SPLUNK_INDEX` | (unset) | Splunk HEC index. |
| `HOPFRAME_SPLUNK_MIN_SEVERITY` | (unset) | Minimum severity to send to Splunk. |
| `HOPFRAME_TOKENS_PATH` | (unset) | Path to the JSON file holding API tokens. |
| `HOPFRAME_OIDC_ISSUER` | (unset) | OIDC issuer (all four OIDC flags must be set to enable). |
| `HOPFRAME_OIDC_CLIENT_ID` | (unset) | OIDC client. |
| `HOPFRAME_OIDC_CLIENT_SECRET` | (unset) | OIDC secret. |
| `HOPFRAME_OIDC_REDIRECT_URL` | (unset) | OIDC redirect. |
| `HOPFRAME_OIDC_DEFAULT_ROLE` | `viewer` | Role assigned at first OIDC login. |

TLS flags on the `control-plane` binary: `--tls-cert`, `--tls-key`, `--tls-client-ca` (mutual TLS). See [Security](security.md).

## Sensor: YAML config

The sensor reads a YAML file (`examples/config/sensor.yaml`). Key blocks:

````yaml
sensor:
  id: hopframe-sensor
  tenant_id: default

upstream:
  url: http://upstream-mcp:8080
  timeout: 30s
listen:
  address: ":7080"
  base_path: /mcp

rules:
  dirs:
    - /etc/hopframe/content
  disabled_rules: []

emitter:
  sink: stdout
  buffer_size: 2048

policy:
  fail_open: true
  block_task_drift: false    # detect-only by default, opt in per deployment
````

Sensor env overrides include `HOPFRAME_MCP_LISTEN_ADDR`, `HOPFRAME_MCP_UPSTREAM_URL`, `HOPFRAME_A2A_LISTEN_ADDR`, `HOPFRAME_A2A_UPSTREAM_URL`, and `HOPFRAME_EMITTER_URL` (control-plane ingest end). The sensor also reads the optional layer-3 LLM judge config (`HOPFRAME_LLM_JUDGE_URL`, `HOPFRAME_LLM_JUDGE_API_KEY`, `HOPFRAME_LLM_JUDGE_MODEL`); the control plane does not. The combined `sensor` runs MCP and A2A in one process so they share a taint tracker.

## Kubernetes: Helm chart values

Key values (full set in `deploy/helm/hopframe/`):

| Value | Default | What it sets |
| --- | --- | --- |
| `controlPlane.replicas` | `1` | Control plane replicas. |
| `controlPlane.retention` | `90d` | Audit retention window. |
| `controlPlane.persistence.size` | `10Gi` | PVC size. |
| `controlPlane.auth.token` | empty | Global bearer token. |
| `controlPlane.auth.tenantTokens` | empty | `tenantID:token` pairs. |
| `controlPlane.auth.roleTokens` | empty | `role:token` pairs. |
| `controlPlane.auth.bootstrapAdmin` | empty | Seeded `username:password`. |
| `controlPlane.signingKey` | empty | Persistent Ed25519 seed. Empty generates a fresh key per boot. |
| `controlPlane.storeDSN` | empty | Postgres DSN for the audit chain. |
| `controlPlane.rekorUrl` | empty | Rekor anchor endpoint. |
| `controlPlane.rateLimitRps` | `0` | Per-IP rate limit. |
| `controlPlane.webhook.url/secret/minSeverity` | empty | SIEM webhook export. |
| `controlPlane.oidc.*` | empty | OIDC SSO (all four values to enable). |
| `mcpSensor.upstream.url` | (required) | The MCP server the sensor forwards to. |
| `mcpSensor.replicas` | `2` | Sensor replicas. |
| `mcpSensor.spool.enabled` | `true` | Local templated spool. |
| `mcpSensor.spool.size` | `1Gi` | Spool size when enabled. |

Persist `signingKey` for any deployment that needs verifiable offline exports; an ephemeral key breaks verification of prior bundles after a restart.

Complete presets live in `examples/config/` (`sensor.yaml`, `secured.env`, `quickstart.env`) and are a safe place to start from.

The seam between them is intentional: the control plane is env-configured, the sensor is file-configured, and Helm wraps both.
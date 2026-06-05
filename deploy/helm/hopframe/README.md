# Hopframe Helm chart

Deploys the Hopframe MCP sensor and control plane on Kubernetes.

## Quick start

```bash
helm upgrade --install hopframe ./deploy/helm/hopframe \
  --namespace hopframe --create-namespace \
  --set mcpSensor.upstream.url=http://my-mcp-server.upstream.svc:8080 \
  --set image.tag=0.1.0
```

## What gets deployed

- **control-plane.** Single-replica `StatefulSet` with a `PersistentVolumeClaim` for the append-only event log. Exposes a `ClusterIP` service on port 7090. Configure retention with `controlPlane.retention` (default 90d).
- **mcp-sensor.** `StatefulSet` (or `Deployment` if spool is disabled) that proxies MCP traffic to `mcpSensor.upstream.url`. Exposes a `ClusterIP` service on port 7080.
- **detection content.** `ConfigMap` placeholder. Replace it to ship curated rules.
- **webhook secret.** Created when `controlPlane.webhook.secret` is set.

## Required values

| Key | Why |
|-----|-----|
| `mcpSensor.upstream.url` | The MCP server the sensor forwards to. The chart fails to render without it. |
| `image.tag` | When empty, defaults to the chart's `appVersion`. |

## Common overrides

```yaml
controlPlane:
  retention: 30d
  webhook:
    url: https://siem.example.com/hopframe
    secret: replace-me
    minSeverity: high

mcpSensor:
  replicas: 4
  spool:
    size: 5Gi
```

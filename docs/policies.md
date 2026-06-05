# Policies

A **rule** matches: "this regex hits this field." A **policy** disposes: "for tenant X on the github MCP server, when rule R fires, block in production but only warn in staging." Hopframe ships rules in YAML; policies live in the control plane and are managed through the API.

This page covers the policy resource model, the resolution rule, and the end-to-end authoring flow for an operator.

## Policy resource model

```json
{
  "id": "pol_1714153012345678901_a8b3f1",
  "name": "block tool poisoning on github MCP",
  "description": "stricter posture for the production github tool surface",
  "version": 1,
  "enabled": true,
  "scope": {
    "tenant_id": "acme",
    "server_name": "github-mcp.acme.svc.cluster.local"
  },
  "selector": {
    "categories": ["tool-poisoning"],
    "min_severity": "high"
  },
  "disposition": {
    "mode": "block"
  }
}
```

| Field | Meaning |
| --- | --- |
| `scope.tenant_id` | Empty matches every tenant. Non-empty narrows to one. |
| `scope.sensor_id` | Empty matches every sensor. Non-empty narrows to one. |
| `scope.server_name` | Empty matches every counterparty. Non-empty narrows to one server. |
| `selector.rule_ids` | Empty matches any rule. Non-empty restricts to listed rule ids. |
| `selector.categories` | Empty matches any category. |
| `selector.min_severity` | Findings below this severity do not satisfy the selector. |
| `selector.methods` | Empty matches any method. Non-empty restricts to listed JSON-RPC methods. |
| `disposition.mode` | `monitor`, `warn`, or `block`. The strongest mode the policy can produce. |

## Resolution

When a sensor evaluates a message:

1. Detection runs. Rules produce findings.
2. The rule-default mode is computed (the strongest mode among the rules that produced findings).
3. Active policies are filtered: scope must match, and the selector must match at least one finding.
4. Among matching policies, the most specific scope wins. Specificity ranks: `server > sensor > tenant > org default`.
5. Within the most-specific group, the strongest mode wins.
6. If no policy matches, the rule-default mode applies.

The resolver code is in `pkg/policy/policy.go::Resolve`. It is shared between sensor and control plane so both ends agree.

## Authoring flow

Assume the operator has a control plane running at `http://hopframe.acme.svc.cluster.local:7090` with an admin token in `HOPFRAME_API_TOKEN`.

### 1. List the current policies

```bash
curl -s -H "Authorization: Bearer $HOPFRAME_API_TOKEN" \
  http://hopframe.acme.svc.cluster.local:7090/v1/policies | jq
```

### 2. Create a policy

```bash
curl -s -X POST \
  -H "Authorization: Bearer $HOPFRAME_API_TOKEN" \
  -H "Content-Type: application/json" \
  http://hopframe.acme.svc.cluster.local:7090/v1/policies \
  -d '{
        "name": "block tool poisoning on github MCP",
        "enabled": true,
        "scope": {"tenant_id": "acme", "server_name": "github-mcp"},
        "selector": {"categories": ["tool-poisoning"], "min_severity": "high"},
        "disposition": {"mode": "block"}
      }' | jq
```

The response includes the assigned `id` and `version`. The change is also written as a synthetic event on the audit chain so operators can trace who changed what.

### 3. Preview the policy against recent traffic

Before flipping a policy to `block`, replay it against the last hour of recorded events to see what it would have caught.

```bash
curl -s -X POST \
  -H "Authorization: Bearer $HOPFRAME_API_TOKEN" \
  -H "Content-Type: application/json" \
  "http://hopframe.acme.svc.cluster.local:7090/v1/policies/$ID/preview" \
  -d '{"limit": 1000}' | jq
```

The output reports how many recorded events would have matched and what dispositions would have applied.

### 4. Update or disable

```bash
curl -s -X PATCH \
  -H "Authorization: Bearer $HOPFRAME_API_TOKEN" \
  -H "Content-Type: application/json" \
  "http://hopframe.acme.svc.cluster.local:7090/v1/policies/$ID" \
  -d '{"disposition": {"mode": "warn"}}'
```

The response shows the bumped version and refreshed `updated_at` / `updated_by`.

### 5. Verify sensors picked it up

```bash
curl -s -H "Authorization: Bearer $HOPFRAME_API_TOKEN" \
  http://hopframe.acme.svc.cluster.local:7090/v1/sensors | jq '.sensors[] | {sensor_id, policy_version, policy_drift}'
```

If `policy_drift` is `false` for every sensor, every sensor has applied the latest version. Drift surfaces stalled or disconnected sensors; investigate the heartbeat path.

## Hierarchy in practice

A common operator pattern is:

- One **org default** policy that blocks `critical` severity across all categories.
- One **tenant** policy per tenant that warns on `high` for `prompt-injection`.
- Per-server **server pin** policies that block `high` severity on a specific risky MCP server.

```json
[
  {"name": "org block critical", "enabled": true,
   "scope": {},
   "selector": {"min_severity": "critical"},
   "disposition": {"mode": "block"}},
  {"name": "acme warn high prompt injection", "enabled": true,
   "scope": {"tenant_id": "acme"},
   "selector": {"categories": ["prompt-injection"], "min_severity": "high"},
   "disposition": {"mode": "warn"}},
  {"name": "acme github block high", "enabled": true,
   "scope": {"tenant_id": "acme", "server_name": "github-mcp"},
   "selector": {"min_severity": "high"},
   "disposition": {"mode": "block"}}
]
```

A `high` prompt-injection finding on the github server in tenant acme resolves: org policy matches (severity ok), tenant policy matches, server pin matches. Server pin has the highest specificity, so its `block` wins. On the slack server in acme, only the tenant policy matches (`warn`).

## Sensor configuration

Sensors fetch policy snapshots from the control plane on boot and on every heartbeat. Configure with:

```bash
HOPFRAME_CONTROL_PLANE_URL=http://hopframe.acme.svc.cluster.local:7090
HOPFRAME_API_TOKEN=<sensor-bound-token>
```

When `HOPFRAME_CONTROL_PLANE_URL` is set, the sensor:

- Issues `GET /v1/policies/active` at startup and applies the snapshot atomically.
- Heartbeats every 30 seconds with its applied policy version.
- On a version mismatch in the heartbeat ack, refetches and swaps in the new snapshot.

The pipeline calls the resolver inline on every message, so a policy change that lands on the sensor takes effect on the next message without a restart.

## What policies do not do (today)

- **They do not author detection rules.** Rules ship in YAML and are versioned in git and via OTA content delivery. Policies decide what to do when those rules fire.
- **They do not encode time-of-day windows.** A staging-only mode is implemented by tagging the staging tenant separately and authoring a policy on that tenant.
- **They do not change rule confidence.** A rule's confidence stays at whatever the YAML declares. If a policy's selector includes a confidence floor, it falls under future work tracked in [roadmap.md](roadmap.md).

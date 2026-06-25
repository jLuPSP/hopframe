# CLI

`hopframe` is the operator CLI. It wraps the same `/v1/*` API the operator UI consumes, so any operation you can do in the UI is reproducible from a shell script or a CI step.

## Install

The CLI is built alongside the rest of the binaries:

```bash
make build
./bin/hopframe help
```

Add `bin/` to your `PATH` for convenience.

## Configure

Two environment variables, each with a flag override. Flags can appear before or after the subcommand and accept either `--flag value` or `--flag=value`.

| Variable | Flag | Default | Purpose |
| --- | --- | --- | --- |
| `HOPFRAME_SERVER` | `--server` | `http://127.0.0.1:7090` | Control-plane base URL |
| `HOPFRAME_API_TOKEN` | `--token` | empty | Bearer token. Required when the control plane has any auth configured. |

```bash
hopframe --server https://hopframe.acme.svc:7090 --token "$TOKEN" events list
hopframe events list --server=https://hopframe.acme.svc:7090 --token="$TOKEN"
```

In the demo mode (no auth), no token is needed.

## Output

JSON to stdout. Pipe through `jq` for human consumption:

```bash
hopframe events list --action block | jq '.records | length'
hopframe rules list | jq '.categories'
hopframe sensors list | jq '.sensors[] | {sensor_id, policy_drift, content_drift}'
```

## Commands

### Status and integrity

```bash
hopframe stats     # chain head + seq + log path
hopframe verify    # re-walk the on-disk chain, report integrity
```

### Events

```bash
hopframe events list                          # last 50 events
hopframe events list --limit 200
hopframe events list --action block
hopframe events list --severity critical --category prompt-injection
hopframe events get 42                        # record 42 with signature + Merkle proof
```

### Policies

```bash
hopframe policies list
hopframe policies get pol_1714153012345678901_a8b3f1
hopframe policies preview pol_1714153012345678901_a8b3f1   # dry-run against recent traffic
hopframe policies create -f policy.json
hopframe policies delete pol_1714153012345678901_a8b3f1
```

Example `policy.json`:

```json
{
  "name": "block-tool-poisoning-on-acme",
  "description": "Stricter posture for the production github tool surface.",
  "enabled": true,
  "scope": {"tenant_id": "acme", "server_name": "github-mcp"},
  "selector": {"categories": ["tool-poisoning"], "min_severity": "high"},
  "disposition": {"mode": "block"}
}
```

### Sensors

```bash
hopframe sensors list                       # fleet inventory with drift markers
```

### Rules

```bash
hopframe rules list                         # the loaded rule pack
hopframe rules list | jq '.rules[] | select(.severity == "critical") | .id'
```

### API tokens

```bash
hopframe tokens list
hopframe tokens mint --name ci-pipeline --role editor --tenant acme
hopframe tokens revoke tok_a3f9b1
```

The mint response includes the secret value once; copy it into your CI's secret store immediately.

### Users

```bash
hopframe users list
hopframe users add --username alice --password 's3cret123' --role admin --tenant acme
hopframe users password alice --password 'newpassword'
```

User accounts only exist when the control plane is configured with `HOPFRAME_USERS_PATH`.

## Use in CI

```yaml
- name: Apply policy bundle
  env:
    HOPFRAME_SERVER: ${{ secrets.HOPFRAME_SERVER }}
    HOPFRAME_API_TOKEN: ${{ secrets.HOPFRAME_API_TOKEN }}
  run: |
    for policy in policies/*.json; do
      hopframe policies create -f "$policy"
    done
```

## Forensic export

Forensic export bundles use a separate binary because their output is a directory, not JSON:

```bash
hopframe-export \
  --control-plane "$HOPFRAME_SERVER" \
  --token "$HOPFRAME_API_TOKEN" \
  --tenant acme \
  --since 2026-01-01T00:00:00Z \
  --until 2026-04-01T00:00:00Z \
  --out evidence-q1-2026 \
  --sign-key data/signing.seed
```

The output directory contains a `manifest.json`, one canonical-bytes file per record, signatures, a Merkle root, and a `VERIFY.md` an auditor can follow without contacting the control plane.

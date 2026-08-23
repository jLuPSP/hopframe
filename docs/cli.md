# CLI reference

The `hopframe` CLI is the operator interface to a control plane. It wraps the same `/v1/*` API the operator UI consumes, so anything you can do in the UI you can do from a shell script or CI step. Output is JSON to stdout; pipe through `jq` for pretty rendering.

## Install

````bash
make build    # builds every binary into ./bin
# or download a prebuilt binary from a GitHub Release
````

## Global flags

`--server` and `--token` may appear anywhere in the argument list (before or after the subcommand), or be set via environment:

| Flag | Environment | Default |
| --- | --- | --- |
| `--server URL` | `HOPFRAME_SERVER` | `http://127.0.0.1:7090` |
| `--token TOKEN` | `HOPFRAME_API_TOKEN` | (unset) |

## Commands

### Stats and integrity

````bash
hopframe stats      # chain head, seq, path
hopframe verify     # re-walk the chain, report integrity
hopframe export     # pull a window of records, sign, write manifest + VERIFY.md
````

### Events

````bash
hopframe events list [--limit 50] [--action block] [--severity high] [--category prompt-injection] [--method tools/call]
hopframe events get <seq>    # fetch a record with signature and Merkle proof
````

Filters combine with `AND`. `events get <seq>` returns the canonical bytes, the Ed25519 signature, and the Merkle proof binding that record to a snapshot of the chain.

### Policies

````bash
hopframe policies list
hopframe policies get <id>
hopframe policies create -f policy.json
hopframe policies preview <id>     # dry-run against the last 1000 events
hopframe policies delete <id>
````

Policy mutations are written to the audit chain, so who changed which policy and when is part of the tamper-evident record.

### Sensors, rules, tokens, users

````bash
hopframe sensors list                            # fleet inventory
hopframe rules list [--category prompt-injection]   # browse the loaded rule packs

hopframe tokens mint --name X --role Y [--tenant Z]
hopframe tokens list
hopframe tokens revoke <id>

hopframe users add --username X --role Y --password PASS
hopframe users list
hopframe users password <username>
````

## Roles

Tokens and users carry one of the RBAC roles: `viewer`, `editor`, `admin`, `owner`. A token may also bind to a tenant (`--tenant Z`), which scopes every read to that tenant and forces `tenant_id` on writes. See [Security](security.md).

## Example

````bash
export HOPFRAME_SERVER=http://hopframe.internal:7090
export HOPFRAME_API_TOKEN=$(openssl rand -hex 32)

hopframe verify
hopframe events list --action block --severity critical
hopframe policies preview prod-strict
hopframe export --output audit-bundle
````

## Building it yourself

The CLI lives in [`cmd/hopframe`](https://github.com/jLuPSP/hopframe/tree/main/cmd/hopframe). Version, commit, and date are injected at link time by goreleaser; a local `go build` reports them as `dev`.

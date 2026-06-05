# Developer guide

For contributors hacking on Hopframe itself. If you only want to use it, start with [Quickstart](quickstart.md).

## Repo layout

```
.
├── bench/                        # benchmark corpus + harness
├── cmd/                          # binaries
│   ├── control-plane/            # ingest + UI + audit chain
│   ├── mcp-sensor/               # inline HTTP MCP sensor
│   ├── mcp-stdio-sensor/         # stdio MCP sensor (wraps a child stdio MCP)
│   ├── a2a-sensor/               # inline HTTP A2A sensor
│   ├── stub-mcp-server/          # fake MCP for the demo
│   ├── stub-stdio-mcp-server/    # fake stdio MCP for the demo
│   ├── stub-a2a-server/          # fake A2A peer for the demo
│   ├── dumb-proxy/               # passthrough proxy used by the blindspot story
│   ├── hopframe-bench/           # detection-pipeline microbenchmark
│   ├── hopframe-export/          # forensic-export CLI
│   └── hopframe/                 # operator CLI
├── content/                      # detection rule packs (YAML, by category)
├── control-plane/
│   ├── api/                      # HTTP handlers + UI HTML embedded
│   ├── behavior/                 # Layer 4 anomaly detection
│   ├── exporter/                 # webhook + Splunk HEC SIEM exporters
│   └── store/                    # hash-chained append-only audit log
├── deploy/                       # Helm chart, Docker Compose
├── docs/                         # mkdocs source (this file lives here)
├── examples/config/              # env presets, sensor YAML examples
├── internal/
│   ├── a2aproxy/                 # inline A2A reverse proxy
│   ├── config/                   # YAML config loading
│   ├── counterparty/             # per-peer risk decay
│   ├── emitter/                  # async emitter, durable spool
│   ├── pipeline/                 # detection pipeline + policy resolver
│   ├── proxy/                    # inline MCP HTTP reverse proxy
│   ├── quarantine/               # tool-quarantine TTL set
│   ├── stdioproxy/               # inline MCP stdio proxy
│   └── taskstate/                # A2A task lifecycle + drift detection
├── pkg/
│   ├── a2a/                      # A2A protocol parsing + agent-card validation
│   ├── audit/                    # Ed25519 signing + Merkle + Rekor anchoring
│   ├── detect/                   # detector interface, heuristic classifier, LLM judge
│   ├── event/                    # wire schema (shared by Go, Python, TS SDKs)
│   ├── mcp/                      # MCP protocol parsing
│   ├── policy/                   # policy resource model + resolver (shared sensor/control plane)
│   │   └── client/               # sensor-side policy client (fetch, hot reload)
│   ├── ruleset/                  # YAML rule pack loader + RE2 evaluator
│   └── taint/                    # cross-protocol taint tracker
├── proto/                        # protocol message reference (informational)
├── scripts/                      # demo launcher, blind-spot story, validate-mcp
├── sdk/
│   ├── python/                   # Python SDK + integrations
│   └── typescript/               # TypeScript SDK + integrations
└── web/                          # reserved for a future asset directory
```

## Setup

```bash
git clone https://github.com/jLuPSP/hopframe.git
cd hopframe
go mod download
make build
make test         # 22 packages, ~1m under -race
```

Python SDK tests:

```bash
cd sdk/python && python3 -m pytest tests/ -q
```

The repo policy: `gofmt -l .` returns nothing, `go test -race -count=1 ./...` passes, `staticcheck ./...` is clean, and there are zero em-dashes anywhere in `*.md` or `*.go` files (the codepoint U+2014). Use periods, commas, parentheses, or colons instead.

## Run the local stack

```bash
make demo                                       # cinematic story, bundled stubs, traffic flowing
make run                                        # boot the stack, no narration, bundled stub MCP
make run UPSTREAM=http://my-mcp:8080            # sensor forwards to your real MCP
make run ENTERPRISE=1                           # auth on, role tokens, signing, sample policies
make run UPSTREAM=http://my-mcp:8080 ENTERPRISE=1  # both
make stop                                       # kill all hopframe processes
```

`make demo` writes data to `/tmp/hopframe-demo`. `make run` writes to `/tmp/hopframe-run`. The UI at http://127.0.0.1:7090 stays alive in all modes.

## Architecture in one paragraph

A sensor (`internal/proxy`, `internal/a2aproxy`, `internal/stdioproxy`) sits inline on protocol traffic and forwards it to an upstream. Before forwarding, the sensor runs the detection pipeline (`internal/pipeline`) which composes detectors from `pkg/detect` (heuristic classifier, optional LLM judge), the rule pack (`pkg/ruleset`), the cross-protocol taint tracker (`pkg/taint`), and the tool-quarantine set (`internal/quarantine`). The pipeline produces a verdict; the policy resolver (`pkg/policy`) picks a final mode (monitor / warn / block) based on which policies match the event scope. Findings flow to the control plane (`control-plane/api`) which writes them to a SHA-256 hash-chained log (`control-plane/store`) and broadcasts to live UI subscribers via SSE. Operators interact via the embedded UI (`control-plane/api/*.html`) or the CLI (`cmd/hopframe`) which both speak the same `/v1/*` API.

Full diagram: [Architecture](architecture.md).

## Adding a detection rule

The fastest contribution. Rules live in `content/<category>/*.yaml`:

```yaml
- id: pi.contrib.your_rule_id
  description: One-line plain-English summary.
  severity: high
  mode: warn
  fields: ["params.**"]
  patterns:
    - 'attempt|to|match'
```

Add a benchmark sample at `bench/corpus/v1.jsonl`:

```json
{"id":"pi-099","category":"prompt-injection","label":"malicious","text":"<the attack string>"}
```

Then `make bench-corpus` to verify the rule fires on the sample without breaking precision.

Format constraints:

- RE2 only: no backreferences (`\1`), no lookarounds (`(?!...)`).
- Patterns are wrapped with `(?i)` unless `case_sensitive: true`.
- Inputs are NFKC-normalized and base64-decoded before matching.

See [CONTRIBUTING.md](https://github.com/jLuPSP/hopframe/blob/main/CONTRIBUTING.md) for the full rule-authoring guide.

## Adding an API endpoint

1. Add the handler in `control-plane/api/`.
2. Register the route in `control-plane/api/api.go::Routes()` with the appropriate `s.auth(s.requireRole(...))` wrapping.
3. Update `routeLabel()` in `api.go` so Prometheus metrics get a stable label (avoid unbounded cardinality from path parameters).
4. Add a test in `control-plane/api/`.
5. If the UI consumes it, add it to the relevant HTML page's JS.
6. If the CLI exposes it, add a subcommand in `cmd/hopframe/main.go`.

## Adding a control-plane resource

If you are adding something CRUDable (like users, tokens, or policies), the existing files are the templates:

- `control-plane/api/policies.go` and `control-plane/store/policystore.go`: JSON-file-backed resource with a listener that writes mutations to the audit chain.
- `control-plane/api/users.go` and `users_api.go`: bcrypt-hashed accounts, sessions, CRUD.
- `control-plane/api/tokens.go`: first-class API tokens with hash-only persistence.

The pattern: a thread-safe in-memory store, atomic JSON file writes, an optional listener for audit-chain emission, and HTTP handlers that wrap the store.

## Wire schema

The event envelope is at `pkg/event/event.go`. Three implementations agree on the same shape:

- Go: `pkg/event` (the canonical definition)
- Python: `sdk/python/hopframe/client.py`
- TypeScript: `sdk/typescript/src/types.ts`

Bump `event.SchemaVersion` only on breaking changes. Additive fields are fine without a bump.

## Releasing

Releases are gated on `workflow_dispatch` against `.github/workflows/release.yaml`. The flow:

1. Update [CHANGELOG.md](https://github.com/jLuPSP/hopframe/blob/main/CHANGELOG.md) with the unreleased changes promoted to a new version section.
2. Tag the commit (`git tag v0.x.0`).
3. Push the tag.
4. Trigger the release workflow manually with `dry_run=false`.

Goreleaser cross-compiles every binary for linux/darwin/windows on amd64/arm64, generates SBOMs via syft, and signs the checksums with cosign keyless via the GitHub OIDC token.

For a snapshot build (no publish), trigger with `dry_run=true`.

## Common debugging commands

```bash
# tail control-plane logs
tail -F /tmp/hopframe-demo/control-plane.log

# inspect the hash chain
./bin/hopframe verify

# replay an event through the detection pipeline
./bin/hopframe-bench --mode replay --corpus bench/corpus/v1.jsonl

# benchmark detection latency
./bin/hopframe-bench --mode latency --count 10000 --parallel 4

# run validation against a real MCP server
make validate VALIDATE_CMD="npx -y @modelcontextprotocol/server-filesystem /tmp"
```

## Documentation

The site at https://jlupsp.github.io/hopframe/ is built from the Markdown files in `docs/` via MkDocs Material. To preview locally:

```bash
pip install mkdocs-material pymdown-extensions
mkdocs serve
```

Then open http://127.0.0.1:8000.

The site builds and deploys automatically via `.github/workflows/docs.yaml` on every push to `main` that touches `docs/`, `mkdocs.yml`, or the workflow itself.

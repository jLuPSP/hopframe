.PHONY: build test cover vet lint clean run-sensor run-stub run-control-plane bench bench-corpus help demo run stop validate

help:
	@printf '%s\n' \
	  'Hopframe make targets' \
	  '' \
	  'Two ways to run it locally:' \
	  '  make demo                       Cinematic story. Bundled stubs, no setup.' \
	  '                                  Reach for this first. ~30 seconds.' \
	  '' \
	  '  make run UPSTREAM=http://...    Hopframe in front of your MCP server.' \
	  '                                  Point your agent at http://127.0.0.1:7080/mcp' \
	  '                                  instead of UPSTREAM. Drop UPSTREAM to use a' \
	  '                                  bundled stub. Optional A2A_UPSTREAM=...' \
	  '                                  wires an A2A sensor on :7081.' \
	  '                                  SECURE=1 turns on auth, role tokens,' \
	  '                                  signing, sample policies. Tokens print on' \
	  '                                  stdout. Use this to kick the Tier 3 surface' \
	  '                                  before Helm-deploying.' \
	  '' \
	  '  make stop                       Stop any running Hopframe processes.' \
	  '' \
	  'Build / test:' \
	  '  make build                      Build all binaries to ./bin' \
	  '  make test                       go test -race ./...' \
	  '  make cover                      Coverage report at ./coverage.html' \
	  '  make bench                      Latency benchmark (10k iterations)' \
	  '  make bench-corpus               Run the detection corpus' \
	  '  make validate VALIDATE_CMD=...  Run an external stdio MCP server through' \
	  '                                  the validator harness' \
	  '  make clean                      Remove ./bin and coverage artifacts'

BIN := bin
PKG := ./...

build:
	@mkdir -p $(BIN)
	go build -o $(BIN)/mcp-sensor ./cmd/mcp-sensor
	go build -o $(BIN)/mcp-stdio-sensor ./cmd/mcp-stdio-sensor
	go build -o $(BIN)/a2a-sensor ./cmd/a2a-sensor
	go build -o $(BIN)/stub-mcp-server ./cmd/stub-mcp-server
	go build -o $(BIN)/stub-stdio-mcp-server ./cmd/stub-stdio-mcp-server
	go build -o $(BIN)/stub-a2a-server ./cmd/stub-a2a-server
	go build -o $(BIN)/control-plane ./cmd/control-plane
	go build -o $(BIN)/dumb-proxy ./cmd/dumb-proxy
	go build -o $(BIN)/hopframe-bench ./cmd/hopframe-bench
	go build -o $(BIN)/hopframe-export ./cmd/hopframe-export
	go build -o $(BIN)/hopframe ./cmd/hopframe

test:
	go test -race -count=1 $(PKG)

cover:
	go test -race -count=1 -coverprofile=coverage.out $(PKG)
	go tool cover -html=coverage.out -o coverage.html

vet:
	go vet $(PKG)

lint: vet

clean:
	rm -rf $(BIN) coverage.out coverage.html

run-sensor:
	go run ./cmd/mcp-sensor --config examples/config/mcp-sensor.yaml

run-stub:
	go run ./cmd/stub-mcp-server --addr :8088

run-control-plane:
	go run ./cmd/control-plane --addr :7090 --log data/events.ndjson

bench:
	go run ./cmd/hopframe-bench --mode latency --count 10000 --parallel 4

bench-corpus:
	go run ./cmd/hopframe-bench --mode corpus --corpus bench/corpus/v1.jsonl

# Two ways to run Hopframe locally.
#
#   demo  Cinematic blind-spot story with bundled stubs. No setup.
#         Reach for this first.
#
#   run   Hopframe in front of an MCP server. Three modifiers:
#           UPSTREAM=http://your-mcp:8080   point at your real MCP
#           A2A_UPSTREAM=http://your-a2a    wire an A2A sensor on :7081
#           SECURE=1                    auth on, role tokens, signing,
#                                           sample policies seeded
#         All three compose. Drop UPSTREAM to use the bundled stub MCP
#         and play with the UI without any setup. The control plane
#         comes up with policies, sensor fleet, and signing turned on
#         in every mode; SECURE adds the multi-tenant + RBAC
#         surface (tokens printed on stdout). OIDC and Rekor stay off
#         in either mode (they need external infra; see
#         examples/config/secured.env to wire them for real).
demo: build
	./scripts/demo.sh

run: build
	UPSTREAM='$(UPSTREAM)' A2A_UPSTREAM='$(A2A_UPSTREAM)' SECURE='$(SECURE)' ./scripts/run.sh

# Stop any running Hopframe processes. Useful when a previous boot
# left ports bound and a follow-up `make demo` would otherwise fail
# with "address in use".
stop:
	@pkill -f 'control-plane|stub-mcp-server|stub-stdio-mcp-server|stub-a2a-server|mcp-sensor|mcp-stdio-sensor|a2a-sensor|dumb-proxy' 2>/dev/null && echo "stopped running hopframe processes" || echo "(nothing was running)"

# Validate against any stdio MCP server. Pass the command via VALIDATE_CMD.
#   make validate VALIDATE_CMD="./bin/stub-stdio-mcp-server"
#   make validate VALIDATE_CMD="npx -y @modelcontextprotocol/server-filesystem /tmp"
#   make validate VALIDATE_CMD="python -m mcp_server_fetch"
validate: build
	./scripts/validate-mcp.sh -- $(VALIDATE_CMD)

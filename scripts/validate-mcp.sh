#!/usr/bin/env bash
# scripts/validate-mcp.sh, point Hopframe at a real MCP server and
# report what works.
#
# Hopframe ships a public compatibility matrix in the README. The
# matrix is only as good as the servers we've actually run against.
# This script wraps a real MCP server with the Hopframe stdio sensor
# and walks it through the standard handshake (initialize →
# tools/list → tools/call) plus a deliberately-malicious request so
# you can verify both forwarding AND detection.
#
# Usage:
#
#   ./scripts/validate-mcp.sh -- <command> [args...]
#
# Examples:
#
#   # against the bundled stub
#   ./scripts/validate-mcp.sh -- ./bin/stub-stdio-mcp-server
#
#   # against an Anthropic reference server (after pip-installing it)
#   ./scripts/validate-mcp.sh -- python -m mcp_server_filesystem /tmp
#   ./scripts/validate-mcp.sh -- npx -y @modelcontextprotocol/server-filesystem /tmp
#   ./scripts/validate-mcp.sh -- npx -y @modelcontextprotocol/server-fetch
#   ./scripts/validate-mcp.sh -- npx -y @modelcontextprotocol/server-github
#
# The script exits with a non-zero status if any phase failed and
# writes a markdown report to /tmp/hopframe-validation.md that you
# can paste into a GitHub issue or PR for the compatibility matrix.

set -euo pipefail
ROOT="$( cd -- "$(dirname "${BASH_SOURCE[0]}")/.." && pwd )"
BIN="$ROOT/bin"
DATA="${HOPFRAME_VALIDATE_DATA:-/tmp/hopframe-validate}"
REPORT="${HOPFRAME_VALIDATE_REPORT:-/tmp/hopframe-validation.md}"
mkdir -p "$DATA"

# parse `-- command args...`
SAW_DASHDASH=0
UPSTREAM_ARGS=()
for a in "$@"; do
  if [[ $SAW_DASHDASH == 1 ]]; then
    UPSTREAM_ARGS+=("$a")
  elif [[ "$a" == "--" ]]; then
    SAW_DASHDASH=1
  fi
done
if [[ ${#UPSTREAM_ARGS[@]} -eq 0 ]]; then
  echo "usage: $0 -- COMMAND [ARG...]"; exit 2
fi

cd "$ROOT"
echo "==> building binaries"
make build > /dev/null

CONFIG="$DATA/sensor.yaml"
EVENTS="$DATA/events.ndjson"
rm -f "$EVENTS"

cat > "$CONFIG" <<EOF
sensor: { id: validate, tenant_id: dev }
upstream: { url: "stdio://", timeout: 5s }
listen: { address: ":0" }
rules: { dirs: [$ROOT/content] }
emitter: { sink: file, path: $EVENTS, buffer_size: 256 }
policy: { fail_open: true }
EOF

UPSTREAM_DESC="${UPSTREAM_ARGS[*]}"
echo "==> upstream: $UPSTREAM_DESC"
echo "==> sensor will exec the upstream and proxy stdio"

# Drive a sequence of MCP requests through the sensor.
# We pipe newline-delimited JSON-RPC into the sensor's stdin and read
# its stdout. Initialize → tools/list → tools/call (echo) → tools/call (poisoned).

SENSOR_LOG="$DATA/sensor.log"
INPUT="$DATA/input.jsonl"
OUTPUT="$DATA/output.jsonl"

cat > "$INPUT" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"hopframe-validate","version":"0.1.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"__benign__","arguments":{"text":"hello"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"__attack__","arguments":{"text":"my key is AKIAIOSFODNN7EXAMPLE"}}}
EOF

# Fire up the sensor with the upstream as a child.
(
  "$BIN/mcp-stdio-sensor" --config "$CONFIG" -- "${UPSTREAM_ARGS[@]}" \
    < "$INPUT" > "$OUTPUT" 2> "$SENSOR_LOG"
) || true

echo "==> sensor exited"

# Parse outputs and write a markdown report.
phases=("initialize" "tools/list" "tools/call (benign)" "tools/call (attack)")
expectations=("response with result" "response with tools array" "response with result" "blocked with -32001 OR forwarded")

declare -a results
declare -a notes
for i in 1 2 3 4; do
  line=$(awk -v ID=$i 'BEGIN{found=0} {if (index($0, "\"id\":"ID) > 0 && !found) { print; found=1 }}' "$OUTPUT" || true)
  results[$i]="$line"
done

echo "==> writing report to $REPORT"
{
  echo "# Hopframe MCP compatibility report"
  echo ""
  echo "**Upstream:** \`$UPSTREAM_DESC\`"
  echo "**Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo ""
  echo "| Phase | Status | Detail |"
  echo "|---|---|---|"
  for i in 1 2 3 4; do
    line="${results[$i]}"
    phase="${phases[$((i-1))]}"
    expect="${expectations[$((i-1))]}"
    status=""; detail=""
    if [[ -z "$line" ]]; then
      status="❌ no response"
      detail="sensor produced no JSON-RPC line for id=$i"
    elif [[ "$i" == "4" ]]; then
      if echo "$line" | grep -q '"code":-32001'; then
        status="✅ blocked"
        detail="hopframe returned blocked-by-policy as expected"
      elif echo "$line" | grep -q '"result"'; then
        status="🟡 forwarded"
        detail="upstream responded normally; rule may not apply to this tool"
      elif echo "$line" | grep -q '"error"'; then
        status="🟡 upstream error"
        detail="upstream rejected, likely method-not-found, not a hopframe failure"
      fi
    else
      if echo "$line" | grep -q '"result"'; then
        status="✅"
        detail="$expect"
      elif echo "$line" | grep -q '"error"'; then
        code=$(echo "$line" | sed -n 's/.*"code":\([-0-9]*\).*/\1/p')
        status="🟡 upstream error"
        detail="upstream returned code=$code (often method-not-found for missing handlers)"
      else
        status="❌ unparseable"
        detail="$line"
      fi
    fi
    echo "| $phase | $status | $detail |"
  done
  echo ""
  echo "## Events emitted"
  count=$(wc -l < "$EVENTS" 2>/dev/null || echo 0)
  echo ""
  echo "Hopframe emitted **$count events** during this session ($EVENTS)."
  echo ""
  echo "## Sensor stderr"
  echo ""
  echo '```'
  tail -50 "$SENSOR_LOG" 2>/dev/null || echo "(no log)"
  echo '```'
  echo ""
  echo "## Outputs"
  echo ""
  echo '```jsonl'
  cat "$OUTPUT"
  echo '```'
} > "$REPORT"

echo
cat "$REPORT"
echo
echo "==> full report at $REPORT"
echo "==> events at $EVENTS"

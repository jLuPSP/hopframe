#!/usr/bin/env sh
# End-to-end check for the ext_authz surface through a real Envoy.
#
# Usage: ./run-test.sh [ENTRY]    (ENTRY defaults to http://localhost:9101)
#
# Case 1 benign tools/call         -> expect HTTP 200, stub upstream answers.
# Case 2 request-side AWS key      -> expect HTTP 403, JSON-RPC blocked-by-policy.
# Case 3 tools/list (response-side)-> expect HTTP 200; ext_authz allows the
#                                     REQUEST and cannot see the response, so a
#                                     poisoned description (when the stub runs
#                                     with --poisoned) would pass here. This is
#                                     the documented blind spot, not a bug.
set -u
ENTRY="${1:-http://localhost:9101}"
hr() { printf '\n========== %s ==========\n' "$1"; }

hr "CASE 1  benign tools/call  (expect 200 + stub result)"
curl -sS -i -X POST "$ENTRY/mcp" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}'

hr "CASE 2  request-side attack  (expect 403 + blocked-by-policy)"
curl -sS -i -X POST "$ENTRY/mcp" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send","arguments":{"text":"AKIAIOSFODNN7EXAMPLE"}}}'

hr "CASE 3  tools/list response-side  (expect 200; blind spot by design)"
curl -sS -i -X POST "$ENTRY/mcp" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/list"}'

printf '\n\n(done)\n'

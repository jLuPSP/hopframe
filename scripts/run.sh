#!/usr/bin/env bash
# scripts/run.sh, "boot Hopframe in front of an MCP server."
#
# This is the script you reach for when you want Hopframe inspecting
# real MCP traffic. It boots two processes by default:
#
#   :7090  control-plane + UI
#   :7080  mcp-sensor   ──forwards──►   $UPSTREAM
#
# Point your agent at http://127.0.0.1:7080/mcp instead of $UPSTREAM
# directly. Open http://127.0.0.1:7090 to see what the sensor catches.
#
# Variables:
#   UPSTREAM        URL of your MCP server. If unset, the bundled stub
#                   MCP boots so you can poke at the UI without setup.
#   A2A_UPSTREAM    Optional A2A peer. When set, the :7081 sensor boots
#                   and forwards to that URL.
#   ENTERPRISE=1    Turn on the Tier 3 surface: a generated admin
#                   token, two tenant tokens (acme + globex), four
#                   role tokens (viewer/editor/admin/owner), per-IP
#                   rate limiting, sample policies, local user
#                   bootstrap. Tokens print on stdout. OIDC + Rekor
#                   stay off (they require external infrastructure;
#                   see examples/config/enterprise.env).

set -uo pipefail

ROOT="$( cd -- "$(dirname "${BASH_SOURCE[0]}")/.." && pwd )"
BIN="$ROOT/bin"
DATA="${HOPFRAME_RUN_DATA:-/tmp/hopframe-run}"
mkdir -p "$DATA"

cd "$ROOT"

UPSTREAM="${UPSTREAM:-}"
A2A_UPSTREAM="${A2A_UPSTREAM:-}"
ENTERPRISE="${ENTERPRISE:-${HOPFRAME_ENTERPRISE:-0}}"

# styling
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  R=$'\033[0m'; B=$'\033[1m'; D=$'\033[2m'; U=$'\033[4m'
  RED=$'\033[31m'; GREEN=$'\033[32m'; CYAN=$'\033[36m'; GREY=$'\033[90m'; MAG=$'\033[35m'
else
  R=""; B=""; D=""; U=""; RED=""; GREEN=""; CYAN=""; GREY=""; MAG=""
fi
ok()    { echo "  ${GREEN}✔${R} $*"; }
phase() { echo; echo "  ${CYAN}▸${R} ${B}$*${R}"; }
hr()    { echo "  ${GREY}────────────────────────────────────────────────────────────────${R}"; }
mint()  { openssl rand -hex 24; }

wait_for() {
  local url=$1 label=$2 deadline=$(( $(date +%s) + 10 ))
  while [[ $(date +%s) -lt $deadline ]]; do
    if curl -sS -m 1 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null | grep -qE '^(200|401)$'; then return 0; fi
    sleep 0.1
  done
  echo "  ${RED}✗${R} $label did not become healthy within 10s"
  return 1
}

# preflight
need_ports=(7090 7080)
[[ -n "$A2A_UPSTREAM" ]] && need_ports+=(7081)
ports_in_use=()
for p in "${need_ports[@]}"; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    ports_in_use+=("$p")
  fi
done
if [ ${#ports_in_use[@]} -gt 0 ]; then
  echo "${RED}${B}ERROR${R} ports already in use: ${ports_in_use[*]}"
  echo "       another stack is probably already running."
  echo "       run ${B}${CYAN}make stop${R} to clean up, then retry."
  exit 1
fi

clear 2>/dev/null || true
echo
if [[ "$ENTERPRISE" == "1" ]]; then
  echo "  ${B}${CYAN}H O P F R A M E${R}   ${GREY}run · enterprise${R}"
else
  echo "  ${B}${CYAN}H O P F R A M E${R}   ${GREY}run${R}"
fi
echo "  ${GREY}──────────────────────────────────────────────────────────────${R}"
if [[ -n "$UPSTREAM" ]]; then
  echo "  ${D}Booting Hopframe in front of your MCP server.${R}"
  echo "  ${D}Point your agent at ${R}${B}http://127.0.0.1:7080/mcp${R} ${D}instead${R}"
  echo "  ${D}of ${R}${B}$UPSTREAM${R} ${D}directly.${R}"
else
  echo "  ${D}No UPSTREAM set; booting the bundled stub MCP server so you can${R}"
  echo "  ${D}poke at the UI without any setup. To protect a real MCP:${R}"
  echo "  ${D}  ${R}${B}make run UPSTREAM=http://your-mcp-server:8080${R}"
fi
if [[ "$ENTERPRISE" == "1" ]]; then
  echo
  echo "  ${D}ENTERPRISE=1: auth on, role tokens, signing on, policies seeded.${R}"
fi
echo

# build
phase "Building binaries"
make build > /dev/null
ok "binaries built ${GREY}($(ls "$BIN" | wc -l | tr -d ' ') artifacts)${R}"

# enterprise mode: mint tokens up front so we can wire them into both
# the control-plane env and the sensor configs in one pass.
ADMIN=""
TENANT_TOKENS=""
ROLE_TOKENS=""
ACME=""; GLOBEX=""; VIEWER=""; EDITOR=""; ADMIN_ROLE=""; OWNER=""
if [[ "$ENTERPRISE" == "1" ]]; then
  phase "Minting tokens"
  ADMIN=$(mint)
  ACME=$(mint); GLOBEX=$(mint)
  VIEWER=$(mint); EDITOR=$(mint); ADMIN_ROLE=$(mint); OWNER=$(mint)
  TENANT_TOKENS="${ACME}:acme,${GLOBEX}:globex"
  ROLE_TOKENS="${VIEWER}:viewer,${EDITOR}:editor,${ADMIN_ROLE}:admin,${OWNER}:owner"
  ok "minted 1 admin + 2 tenant + 4 role tokens"
fi

PIDS=()
cleanup() {
  echo
  echo "  ${GREY}Stopping...${R}"
  for pid in "${PIDS[@]:-}"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  pkill -P $$ 2>/dev/null || true
  wait 2>/dev/null || true
  echo "  ${GREY}Stopped.${R}"
}
trap cleanup EXIT INT TERM

phase "Booting services"

# control plane env: always-on Tier 1 (policies, fleet, signing,
# content), plus enterprise-only blocks when ENTERPRISE=1.
cp_env=(
  "HOPFRAME_POLICY_PATH=$DATA/policies.json"
  "HOPFRAME_SENSOR_FLEET=1"
  "HOPFRAME_SIGNING_KEY=$DATA/signing.seed"
  "HOPFRAME_CONTENT_ROOT=$ROOT/content"
)
if [[ "$ENTERPRISE" == "1" ]]; then
  cp_env+=(
    "HOPFRAME_API_TOKEN=$ADMIN"
    "HOPFRAME_TENANT_TOKENS=$TENANT_TOKENS"
    "HOPFRAME_ROLE_TOKENS=$ROLE_TOKENS"
    "HOPFRAME_USERS_PATH=$DATA/users.json"
    "HOPFRAME_BOOTSTRAP_ADMIN=admin:enterprise-demo"
    "HOPFRAME_TOKENS_PATH=$DATA/tokens.json"
    "HOPFRAME_RATE_LIMIT_RPS=500"
  )
fi
env "${cp_env[@]}" "$BIN/control-plane" --addr :7090 --log "$DATA/events.ndjson" --retention 24h \
  > "$DATA/control-plane.log" 2>&1 &
PIDS+=($!)
wait_for "http://127.0.0.1:7090/healthz" "control-plane"
if [[ "$ENTERPRISE" == "1" ]]; then
  ok "control plane    ${GREY}:7090${R}  ${D}auth required${R}"
else
  ok "control plane    ${GREY}:7090${R}  ${D}→${R}  ${U}http://127.0.0.1:7090${R}"
fi

# upstream MCP: real one if UPSTREAM is set, otherwise a stub
if [[ -z "$UPSTREAM" ]]; then
  "$BIN/stub-mcp-server" --addr :8088 --poisoned > "$DATA/stub-mcp.log" 2>&1 &
  PIDS+=($!)
  wait_for "http://127.0.0.1:8088/healthz" "stub MCP"
  UPSTREAM="http://127.0.0.1:8088"
  ok "stub MCP         ${GREY}:8088${R}  ${D}(bundled, returns a poisoned tools/list)${R}"
else
  ok "real MCP         ${B}$UPSTREAM${R}  ${D}(your upstream)${R}"
fi

MCP_CFG="$DATA/mcp-sensor.yaml"
{
  echo "sensor: { id: hopframe-run-mcp, tenant_id: default }"
  echo "upstream: { url: $UPSTREAM, timeout: 30s }"
  echo "listen: { address: \":7080\", base_path: /mcp }"
  echo "rules: { dirs: [$ROOT/content] }"
  echo "emitter:"
  echo "  sink: http"
  echo "  url: http://127.0.0.1:7090/v1/events"
  echo "  buffer_size: 1024"
  echo "  spool_path: $DATA/mcp-spool.ndjson"
  echo "  replay_interval: 2s"
  if [[ "$ENTERPRISE" == "1" ]]; then echo "  bearer_token: $ADMIN"; fi
  echo "policy: { fail_open: true }"
} > "$MCP_CFG"

sensor_env=("HOPFRAME_CONTROL_PLANE_URL=http://127.0.0.1:7090")
[[ "$ENTERPRISE" == "1" ]] && sensor_env+=("HOPFRAME_API_TOKEN=$ADMIN")
env "${sensor_env[@]}" "$BIN/mcp-sensor" --config "$MCP_CFG" > "$DATA/mcp-sensor.log" 2>&1 &
PIDS+=($!)
wait_for "http://127.0.0.1:7080/healthz" "mcp-sensor"
ok "hopframe sensor  ${GREY}:7080${R}  ${D}layered detection, signed audit, taint tracking${R}"

# Optional A2A sensor when A2A_UPSTREAM is set.
if [[ -n "$A2A_UPSTREAM" ]]; then
  A2A_CFG="$DATA/a2a-sensor.yaml"
  {
    echo "sensor: { id: hopframe-run-a2a, tenant_id: default }"
    echo "upstream: { url: $A2A_UPSTREAM, timeout: 30s }"
    echo "listen: { address: \":7081\", base_path: / }"
    echo "rules: { dirs: [$ROOT/content] }"
    echo "emitter:"
    echo "  sink: http"
    echo "  url: http://127.0.0.1:7090/v1/events"
    echo "  buffer_size: 1024"
    echo "  spool_path: $DATA/a2a-spool.ndjson"
    echo "  replay_interval: 2s"
    if [[ "$ENTERPRISE" == "1" ]]; then echo "  bearer_token: $ADMIN"; fi
    echo "policy: { fail_open: true }"
  } > "$A2A_CFG"
  env "${sensor_env[@]}" "$BIN/a2a-sensor" --config "$A2A_CFG" > "$DATA/a2a-sensor.log" 2>&1 &
  PIDS+=($!)
  wait_for "http://127.0.0.1:7081/healthz" "a2a-sensor"
  ok "a2a sensor       ${GREY}:7081${R}  ${D}→${R}  ${B}$A2A_UPSTREAM${R}"
fi

# Enterprise: seed sample policies on each tenant via the admin token.
if [[ "$ENTERPRISE" == "1" ]]; then
  phase "Seeding sample policies"
  seed() {
    curl -sS -X POST http://127.0.0.1:7090/v1/policies \
      -H "Authorization: Bearer $ADMIN" \
      -H 'Content-Type: application/json' -d "$1" > /dev/null 2>&1 || true
  }
  seed '{"name":"org-block-critical","enabled":true,"scope":{},"selector":{"min_severity":"critical"},"disposition":{"mode":"block"}}'
  seed '{"name":"acme-warn-prompt-injection","enabled":true,"scope":{"tenant_id":"acme"},"selector":{"categories":["prompt-injection"],"min_severity":"high"},"disposition":{"mode":"warn"}}'
  seed '{"name":"acme-block-tool-poisoning","enabled":true,"scope":{"tenant_id":"acme"},"selector":{"categories":["tool-poisoning"]},"disposition":{"mode":"block"}}'
  seed '{"name":"globex-monitor-pii","enabled":true,"scope":{"tenant_id":"globex"},"selector":{"categories":["pii-leakage"]},"disposition":{"mode":"monitor"}}'
  ok "seeded 4 sample policies on tenants ${B}acme${R}, ${B}globex${R}"
fi

# Continuous traffic generator. Only when there's no real upstream;
# otherwise we'd be hammering the user's MCP for no reason.
if [[ "$UPSTREAM" == "http://127.0.0.1:8088" ]]; then
  phase "Starting continuous traffic generator"
  if [[ "$ENTERPRISE" == "1" ]]; then
    "$ROOT/scripts/demo-traffic.sh" --continuous --token "$ADMIN" \
      --mcp http://127.0.0.1:7080/mcp \
      > "$DATA/traffic.log" 2>&1 &
  else
    "$ROOT/scripts/demo-traffic.sh" --continuous \
      --mcp http://127.0.0.1:7080/mcp \
      > "$DATA/traffic.log" 2>&1 &
  fi
  PIDS+=($!)
  ok "background traffic flowing ${GREY}(log: $DATA/traffic.log)${R}"
fi

echo
hr
echo

if [[ "$ENTERPRISE" == "1" ]]; then
  echo "  ${B}Tokens${R}                ${D}use these as Authorization: Bearer <token>${R}"
  echo
  printf "    %-13s %s\n" "admin"        "$ADMIN"
  printf "    %-13s %s\n" "tenant acme"  "$ACME"
  printf "    %-13s %s\n" "tenant globex" "$GLOBEX"
  printf "    %-13s %s\n" "viewer"       "$VIEWER"
  printf "    %-13s %s\n" "editor"       "$EDITOR"
  printf "    %-13s %s\n" "admin role"   "$ADMIN_ROLE"
  printf "    %-13s %s\n" "owner"        "$OWNER"
  echo
  echo "  ${B}Local user${R}            ${D}sign in at http://127.0.0.1:7090${R}"
  echo "    username      ${B}admin${R}"
  echo "    password      ${B}enterprise-demo${R}   ${GREY}(rotate via /v1/users/admin/password)${R}"
  echo
fi

echo "  ${B}Wire your agent up${R}"
if [[ "$UPSTREAM" == "http://127.0.0.1:8088" ]]; then
  echo "    ${D}Once you point an agent at ${B}http://127.0.0.1:7080/mcp${D},${R}"
  echo "    ${D}every request flows through Hopframe before reaching the MCP.${R}"
else
  echo "    ${D}Change your agent's MCP URL from${R}"
  echo "      ${B}$UPSTREAM${R}"
  echo "    ${D}to${R}"
  echo "      ${B}http://127.0.0.1:7080/mcp${R}"
  echo "    ${D}and you're done. Hopframe inspects every request and response.${R}"
fi
echo
echo "  ${B}Open the UI${R}"
echo "    ${CYAN}${U}http://127.0.0.1:7090${R}              ${GREY}live event stream${R}"
echo "    ${CYAN}${U}http://127.0.0.1:7090/dashboard${R}    ${GREY}operational charts${R}"
echo "    ${CYAN}${U}http://127.0.0.1:7090/policies${R}     ${GREY}policy authoring${R}"
echo "    ${CYAN}${U}http://127.0.0.1:7090/records${R}      ${GREY}per-record signature inspector${R}"
echo
echo "  ${GREY}Logs at $DATA${R}"
echo "  ${GREY}Press Ctrl-C to stop, or run 'make stop' from another shell.${R}"
echo

wait "${PIDS[0]}"

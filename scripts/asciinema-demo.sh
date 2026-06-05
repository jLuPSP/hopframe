#!/usr/bin/env bash
# Wrapper that runs the cinematic demo, then exits cleanly so the
# asciinema cast has a finite length. Skips the traffic generator
# (no point in recording a forever-loop) and SIGINTs the demo
# script after the result panel + UI banner have rendered.
#
# Used by `asciinema rec --command scripts/asciinema-demo.sh`.

set -uo pipefail

ROOT="$( cd -- "$(dirname "${BASH_SOURCE[0]}")/.." && pwd )"
cd "$ROOT"

./scripts/demo.sh --no-traffic &
DEMO_PID=$!

# Cinematic story takes ~30s after build/boot; give the whole script
# 75s budget end-to-end to render through the "Open the UI" panel.
sleep 75
kill -INT "$DEMO_PID" 2>/dev/null || true
wait 2>/dev/null || true

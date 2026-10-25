#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"

while sleep 15; do
  free -m | awk -v t="$(date -u +%T)" '/^Mem:/ { printf "memory %s UTC: %d of %d MiB used, %d available\n", t, $3, $2, $7 }' |
    tee -a "$RUNNER_TEMP/memory.log"
done &
sampler=$!
trap 'kill "$sampler" 2>/dev/null || true' EXIT
task --silent test:race -- -json | tee "$RUNNER_TEMP/test.json" | bash .github/scripts/failed-tests.sh --text

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"

task check 2>&1 | tee "$RUNNER_TEMP/test.log"

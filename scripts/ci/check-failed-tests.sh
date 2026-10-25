#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"
: "${GITHUB_STEP_SUMMARY:?set GITHUB_STEP_SUMMARY}"

if [ ! -s "$RUNNER_TEMP/test.log" ]; then
  exit 0
fi
printf '### Failed tests – %s\n\n' "$GITHUB_JOB" >>"$GITHUB_STEP_SUMMARY"
bash .github/scripts/failed-tests.sh "$RUNNER_TEMP/test.log" "$GITHUB_STEP_SUMMARY"

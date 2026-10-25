#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"
: "${GITHUB_STEP_SUMMARY:?set GITHUB_STEP_SUMMARY}"

printf '### Failed tests – %s\n\n' "$GITHUB_JOB" >>"$GITHUB_STEP_SUMMARY"
if [ -s "$RUNNER_TEMP/test.json" ]; then
  bash .github/scripts/failed-tests.sh "$RUNNER_TEMP/test.json" "$GITHUB_STEP_SUMMARY"
fi
if [ -s "$RUNNER_TEMP/memory.log" ]; then
  {
    printf '\n#### Memory, the last two minutes\n\n```text\n'
    tail -n 8 "$RUNNER_TEMP/memory.log"
    printf '```\n'
  } >>"$GITHUB_STEP_SUMMARY"
fi
oom=$(sudo dmesg 2>/dev/null | grep -iE 'out of memory|oom-kill|killed process' | tail -n 5 || true)
if [ -n "$oom" ]; then
  printf '::error title=out of memory::%s\n' "${oom//$'\n'/%0A}"
fi

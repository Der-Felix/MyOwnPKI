#!/usr/bin/env bash
# Shared by agent-e2e-apache.sh and agent-e2e-haproxy.sh (docs/PHASE3.md §17,
# step 69). Source this file; it runs nothing by itself.
#
# The tests start the distribution's own Apache or HAProxy with a private
# configuration, pid file and a free loopback port, as the user of the job. An
# installed system service is never signaled. They run only with the switch
# variable of the service set, which this function does.

# e2e_services_run LABEL SWITCH "BINARY..." TEST...
# Runs the named tests of ./internal/agent three times with the e2etest tag.
# A skipped or missing test is an error. Lines the tests print about what the
# real service did (OBSERVED) and where the notes of the recipe are behind
# (NOTES-UPDATE) go to the job summary and, the second kind, to a warning
# annotation. Nothing printed here carries a key: the tests log file paths,
# fingerprints and service messages only.
e2e_services_run() {
  local label=$1 switch=$2 binaries=$3 binary test pattern log status=0
  shift 3
  for binary in $binaries; do
    if [ ! -x "$binary" ]; then
      echo "::error::$binary is missing: install the $label package of the distribution first" >&2
      return 1
    fi
  done
  pattern=$(printf '%s|' "$@")
  pattern="^(${pattern%|})\$"
  log=$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/agent-e2e-$label.XXXXXX")
  env "$switch=1" go test -count=3 -timeout 10m -v -tags e2etest ./internal/agent -run "$pattern" 2>&1 | tee "$log" || status=$?

  for test in "$@"; do
    if ! grep -q -- "^--- PASS: $test " "$log"; then
      echo "::error::$test did not pass (missing, skipped or failed)" >&2
      status=1
    fi
  done
  if grep -q -- '^--- SKIP' "$log"; then
    echo "::error::a $label test was skipped although $switch=1 is set" >&2
    status=1
  fi

  sed -n 's/.*\(NOTES-UPDATE.*\)/\1/p' "$log" | awk '!seen[$0]++' | while IFS= read -r line; do
    echo "::warning title=Recipe notes are behind the real $label::$line"
  done
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      printf '### Real %s: what the tests observed\n\n```text\n' "$label"
      sed -n 's/.*\(OBSERVED.*\)/\1/p;s/.*\(NOTES-UPDATE.*\)/\1/p' "$log" | awk '!seen[$0]++'
      printf '```\n'
    } >>"$GITHUB_STEP_SUMMARY"
  fi
  rm -f "$log"
  return "$status"
}

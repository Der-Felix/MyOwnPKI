#!/usr/bin/env bash
# Lists the functions that no binary and no test reaches (golang.org/x/tools/cmd/deadcode) and fails
# when one of them is not on the reviewed list scripts/ci/deadcode-known.txt.
#
# Usage: bash scripts/ci/deadcode.sh
#
# The tool runs through the module cache with the version go.mod already requires for golang.org/x/tools;
# it adds no `tool` line and changes neither go.mod nor go.sum. Every test counts as a root (-test), so a
# helper that only tests call is not reported: it is reachable. Not part of `task check`.
#
# Lines are compared without the line and column and with forward slashes, so an edit above a reviewed
# function does not make it "new" and Windows and Linux print the same. The results depend on the build
# tags of the machine: this run uses the default tags (no e2etest, no conformance).
#
# Exit status: 0 nothing new, 1 a function is not on the list, 2 the tool failed.
set -euo pipefail
cd "$(dirname "$0")/../.."

known_file=${DEADCODE_KNOWN_FILE:-scripts/ci/deadcode-known.txt}

if ! raw=$(go run golang.org/x/tools/cmd/deadcode -test ./...); then
  echo "deadcode: the tool failed" >&2
  exit 2
fi

found=$(printf '%s\n' "$raw" | sed -E -e 's#[\\]#/#g' -e 's/:[0-9]+:[0-9]+:/:/' | sort -u | grep -v '^$' || true)
known=$(grep -v -E '^[[:space:]]*(#|$)' "$known_file" | sort -u || true)

new=
while IFS= read -r line; do
  [ -n "$line" ] || continue
  if ! grep -Fqx -- "$line" <<<"$known"; then
    new+="$line"$'\n'
  fi
done <<<"$found"

if [ -n "$new" ]; then
  echo "deadcode: not reached by any binary or test, and not on the reviewed list ($known_file):" >&2
  printf '%s' "$new" >&2
  echo "Delete the function, move it into a _test.go file, or review it and add the line to the list." >&2
  exit 1
fi
echo "deadcode: nothing new ($(printf '%s' "$known" | grep -c . || true) reviewed)"

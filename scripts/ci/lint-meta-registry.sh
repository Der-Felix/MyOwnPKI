#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

workflow=${CI_WORKFLOW_FILE:-.github/workflows/ci.yml}
registry=${CI_REGISTRY_FILE:-scripts/ci/local.sh}
failures=0
tmp=
cleanup() {
  [ -z "$tmp" ] || rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
  echo "registry check: $*" >&2
  failures=$((failures + 1))
}

references() {
  sed -nE 's/.*(bash|source)[[:space:]]+(scripts\/ci\/[A-Za-z0-9._-]+\.sh).*/\2/p' "$1"
}

workflow_scripts=$(references "$workflow")
registry_scripts=$(references "$registry")

# Pure diagnostics, not local verification steps. The first and third run only
# on failure; the race report also runs after cancellation to name hung tests.
error_steps=(
  'check-failed-tests.sh|if: failure()'
  'race-failed-tests.sh|if: failure() || cancelled()'
  'install-service-log.sh|if: failure()'
)
error_step_names='check-failed-tests.sh race-failed-tests.sh install-service-log.sh'
for entry in "${error_steps[@]}"; do
  IFS='|' read -r script condition <<<"$entry"
  if ! grep -F -B2 "run: bash scripts/ci/$script" "$workflow" | grep -Fqx "        $condition"; then
    fail "$script is not guarded by exactly '$condition'"
  fi
done

while IFS= read -r script; do
  [ -n "$script" ] || continue
  case " $error_step_names " in
    *" ${script##*/} "*) continue ;;
  esac
  if ! grep -Fqx -- "$script" <<<"$registry_scripts"; then
    fail "$script is called by ci.yml but missing from the local registry"
  fi
done <<<"$workflow_scripts"

while IFS= read -r script; do
  [ -n "$script" ] || continue
  if [ ! -f "$script" ]; then
    fail "registry references missing script $script"
  fi
done <<<"$registry_scripts"

used_scripts=$(
  {
    references "$workflow"
    references "$registry"
    references Taskfile.yml
    for file in scripts/ci/*.sh; do
      references "$file"
    done
  } | sort -u
)
for file in scripts/ci/*.sh; do
  if ! grep -Fqx -- "$file" <<<"$used_scripts"; then
    fail "$file is not used by ci.yml, the registry, Taskfile.yml or another CI script"
  fi
done

[ "$failures" -eq 0 ] || exit 1

if [ "${1:-}" = --self-test ]; then
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-ci-registry.XXXXXX")
  while IFS= read -r line; do
    case $line in
      *"  'check|check|"*) continue ;;
    esac
    printf '%s\n' "$line"
  done <"$registry" >"$tmp/local.sh"
  if CI_REGISTRY_FILE="$tmp/local.sh" bash "$0" >/dev/null 2>&1; then
    echo 'registry check: self-test accepted a missing association' >&2
    exit 1
  fi
  echo 'registry self-test: missing association rejected'
fi

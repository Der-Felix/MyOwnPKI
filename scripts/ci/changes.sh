#!/usr/bin/env bash
# Decides whether a pull request changes more than documentation, so ci.yml
# can skip the heavy jobs for it (job `changes`; CONTRIBUTING.md).
#
#   changes.sh              Read NUL-separated paths on stdin, print
#                           code=false when EVERY path is documentation,
#                           else code=true.
#   changes.sh --pr         The workflow entry point: print code=true for every
#                           event except pull_request (main is never skipped);
#                           for a pull request, classify
#                           `git diff PR_BASE_SHA...PR_HEAD_SHA`. Anything
#                           unexpected (bad SHA, git error, empty diff) prints
#                           code=true: when in doubt, run everything.
#   changes.sh --self-test  Table of cases, also run by the changes job.
#
# Documentation (the whole allowlist, deliberately small):
#   .claude/**                 Claude skill files and project settings
#   docs/**/*.md               documents below docs/ (images there are code)
#   *.md in the repository root (README, CHANGELOG, CLAUDE.md, ...)
# Everything else is code, including every other *.md deeper in the tree
# (presets/README.md, assets/brand/README.md), .github/**, scripts/**, deploy/**.
#
# Stdout carries only the code=... line (it goes to $GITHUB_OUTPUT); the
# diagnostics go to stderr. File names are attacker input: they are printed
# with %q so a name cannot smuggle workflow commands into the log.
set -euo pipefail

# is_doc PATH: succeeds if the path is on the allowlist.
is_doc() {
  case $1 in
    .claude/*) return 0 ;;
    docs/*.md) return 0 ;;
    */*) return 1 ;; # any other path below a directory is code
    *.md) return 0 ;;
    *) return 1 ;;
  esac
}

# classify: NUL-separated paths on stdin -> code=true|false on stdout.
classify() {
  local path count=0 shown=0 code=false
  while IFS= read -r -d '' path; do
    count=$((count + 1))
    if ! is_doc "$path"; then
      code=true
      if [ "$shown" -lt 5 ]; then
        printf 'changes: code path: %q\n' "$path" >&2
        shown=$((shown + 1))
      fi
    fi
  done
  if [ "$count" -eq 0 ]; then
    echo 'changes: empty diff, treated as code' >&2
    code=true
  fi
  echo "changes: $count changed path(s), code=$code" >&2
  echo "code=$code"
}

# pull_request: the workflow entry point (see the header).
pull_request() {
  local event=${GITHUB_EVENT_NAME:-} base=${PR_BASE_SHA:-} head=${PR_HEAD_SHA:-} list
  if [ "$event" != pull_request ]; then
    echo "changes: event '$event' always runs everything" >&2
    echo 'code=true'
    return 0
  fi
  if ! [[ $base =~ ^[0-9a-f]{40,64}$ && $head =~ ^[0-9a-f]{40,64}$ ]]; then
    echo 'changes: missing or malformed base/head SHA, treated as code' >&2
    echo 'code=true'
    return 0
  fi
  list=$(mktemp "${TMPDIR:-/tmp}/myownpki-changes.XXXXXX")
  # --no-renames: a rename lists the old and the new name, so moving a code
  # file to docs/x.md is still a code change. Three dots: the PR's own
  # changes since the merge base, not what main gained meanwhile.
  if ! git diff --name-only --no-renames -z "$base...$head" -- >"$list" 2>/dev/null; then
    rm -f "$list"
    echo 'changes: git diff failed, treated as code' >&2
    echo 'code=true'
    return 0
  fi
  classify <"$list"
  rm -f "$list"
}

self_test() {
  local self tmp failures=0
  self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")

  # expect NAME WANT PATH...: NUL-separated paths on stdin.
  expect() {
    local name=$1 want=$2 got
    shift 2
    got=$(printf '%s\0' "$@" | bash "$self" 2>/dev/null)
    if [ "$got" != "code=$want" ]; then
      echo "changes self-test FAILED: $name: got '$got', want 'code=$want'" >&2
      failures=$((failures + 1))
    fi
  }

  expect 'docs only' false docs/OPERATIONS.md README.md CHANGELOG.md
  expect 'docs in a subdirectory' false docs/trials/notes.md
  expect 'docs and one Go file' true docs/OPERATIONS.md internal/x.go
  expect 'only a Claude skill file' false .claude/skills/x/SKILL.md
  expect 'Claude settings' false .claude/settings.json
  expect 'workflow' true .github/workflows/ci.yml
  expect 'CI script' true scripts/ci/changes.sh
  expect 'README deeper in the tree' true assets/brand/README.md
  expect 'presets README' true presets/README.md
  expect 'image in docs' true docs/screenshots/login.png
  expect 'non-Markdown in docs' true docs/run.sh
  expect 'root file that is not Markdown' true Taskfile.yml
  expect 'root LICENSE' true LICENSE
  expect 'upper-case extension' true README.MD
  expect 'like .claude but not' true .claudex/a.md
  expect 'single code file' true go.mod
  expect 'space in the name' false 'docs/with space.md'
  expect 'space in a code name' true 'docs/with space.sh'
  expect 'quotes and dollar' false "docs/it's \$(x); y.md"
  expect 'newline in a docs name' false $'docs/a\nb.md'
  expect 'newline cannot hide a code name' true $'docs/a.md\ninternal/x.go'
  expect 'glob characters stay literal' true 'docs/*.sh'
  expect 'rename: old name is code' true scripts/ci/old.sh docs/new.md
  expect 'rename within docs' false docs/old.md docs/new.md

  if [ "$(printf '' | bash "$self" 2>/dev/null)" != code=true ]; then
    echo 'changes self-test FAILED: empty diff must be code=true' >&2
    failures=$((failures + 1))
  fi

  # The git entry point against a throwaway repository.
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-changes-test.XXXXXX")
  (
    set -e
    export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
    export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@localhost GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@localhost
    cd "$tmp"
    git init -q repo
    cd repo
    commit() { git add -A && git commit -q -m "$1" && git rev-parse HEAD; }
    mkdir docs scripts
    echo a >docs/a.md
    echo b >README.md
    printf '#!/bin/sh\n' >scripts/x.sh
    root=$(commit root)

    run() { # run NAME WANT EVENT BASE HEAD
      local got
      got=$(GITHUB_EVENT_NAME=$3 PR_BASE_SHA=$4 PR_HEAD_SHA=$5 bash "$self" --pr 2>/dev/null)
      if [ "$got" != "code=$2" ]; then
        echo "changes self-test FAILED: git: $1: got '$got', want 'code=$2'" >&2
        exit 1
      fi
    }

    git checkout -q --detach "$root"
    echo more >>docs/a.md
    echo "it's" >"docs/with space.md"
    echo c >>README.md
    docs_head=$(commit docs)
    run 'docs-only pull request' false pull_request "$root" "$docs_head"
    run 'push is never skipped' true push "$root" "$docs_head"
    run 'schedule is never skipped' true schedule "$root" "$docs_head"
    run 'workflow_dispatch is never skipped' true workflow_dispatch "$root" "$docs_head"
    run 'identical base and head' true pull_request "$docs_head" "$docs_head"
    run 'malformed SHA' true pull_request "--output=x" "$docs_head"
    run 'unknown SHA' true pull_request "$root" 0123456789012345678901234567890123456789

    git checkout -q --detach "$root"
    echo d >internal.go
    code_head=$(commit code)
    run 'code file' true pull_request "$root" "$code_head"

    # A rename out of the code tree into docs/ keeps the old name in the diff.
    git checkout -q --detach "$root"
    git mv scripts/x.sh docs/x.md
    rename_head=$(commit rename)
    run 'rename from code to docs' true pull_request "$root" "$rename_head"

    # main moved on with a code change after the branch point: not ours.
    git checkout -q --detach "$root"
    echo e >moved.go
    moved_base=$(commit main-moves)
    run 'docs-only pull request, base moved on' false pull_request "$moved_base" "$docs_head"
  ) || failures=$((failures + 1))
  rm -rf "$tmp"

  if [ "$failures" -ne 0 ]; then
    echo "changes self-test: $failures failure(s)" >&2
    return 1
  fi
  echo 'changes self-test: all cases passed'
}

case ${1:-} in
  '') classify ;;
  --pr) pull_request ;;
  --self-test) self_test ;;
  *)
    echo 'usage: changes.sh [--pr | --self-test]  (NUL-separated paths on stdin otherwise)' >&2
    exit 2
    ;;
esac

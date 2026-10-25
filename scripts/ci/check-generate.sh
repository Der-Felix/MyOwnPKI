#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

if [ -z "$(git status --porcelain)" ]; then
  exec task generate:check
fi

isolated=$(mktemp -d "${TMPDIR:-/tmp}/myownpki-generate.XXXXXX")
trap 'rm -rf "$isolated"' EXIT
printf 'Dirty worktree: checking generated code in an isolated copy.\n'
tar \
  --exclude=.git --exclude=.tools --exclude=bin --exclude=dist \
  --exclude=.env --exclude='.env.*' --exclude='*.local.yaml' --exclude='*.local.toml' \
  --exclude=CLAUDE.local.md --exclude=settings.local.json --exclude=data --exclude=var \
  -cf - . | tar -xf - -C "$isolated"
git -C "$isolated" init --quiet
git -C "$isolated" add -A
git -C "$isolated" -c user.name='CI local' -c user.email='ci-local@localhost' commit --quiet -m baseline
task --dir "$isolated" generate:check

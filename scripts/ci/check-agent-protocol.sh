#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

git fetch --no-tags origin main:refs/remotes/origin/main
if git cat-file -e origin/main:buf.yaml 2>/dev/null; then
  go run ./internal/tools/buf breaking --against '.git#branch=origin/main'
else
  echo 'main has no agent protocol yet; the introduction in v0.3.0 is the compatibility baseline'
fi

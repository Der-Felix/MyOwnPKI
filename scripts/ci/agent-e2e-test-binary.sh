#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

output=$1
package=$2
mkdir -p "$(dirname "$output")"
GOOS=${GOOS:-linux} GOARCH=${GOARCH:-amd64} CGO_ENABLED=0 \
  go test -c -tags e2etest -o "$output" "$package"

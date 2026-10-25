#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"

go build -trimpath -o "$RUNNER_TEMP/update/myownpki" \
  -ldflags "-X github.com/Der-Felix/MyOwnPKI/internal/version.version=v0.2.1-ci.update" ./cmd/myownpki

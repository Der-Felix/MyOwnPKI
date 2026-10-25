#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

go test -count=1 -run '^TestWindowsHelper' -v ./internal/publish/

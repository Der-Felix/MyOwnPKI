#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

goreleaser release --snapshot --clean --skip=sign,docker,sbom

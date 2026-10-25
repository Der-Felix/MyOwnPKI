#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"

goroot=$(go env GOROOT)
modcache=$(go env GOMODCACHE)
mkdir -p "$RUNNER_TEMP/agent-go-cache" "$RUNNER_TEMP/agent-tmp"
docker run --rm --network host \
  --env PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  --env HOME=/tmp --env GOPATH=/tmp/gopath --env GOMODCACHE=/go/pkg/mod \
  --env GOCACHE=/tmp/go-cache --env GOFLAGS=-mod=readonly --env GOTOOLCHAIN=local \
  --env CGO_ENABLED=0 --env MYOWNPKI_REQUIRE_NGINX=1 \
  --volume "$PWD:/src:ro" --volume "$goroot:/usr/local/go:ro" \
  --volume "$modcache:/go/pkg/mod:ro" \
  --volume "$RUNNER_TEMP/agent-go-cache:/tmp/go-cache" \
  --volume "$RUNNER_TEMP/agent-tmp:/tmp" \
  --workdir /src \
  nginx:1.29.2-trixie@sha256:029d4461bd98f124e531380505ceea2072418fdf28752aa73b7b273ba3048903 \
  bash -c 'nginx -v && go test -count=1 -v ./internal/server -run "^(TestAgentEndToEnd|TestRenewNowOverRESTServesNewCertificate)$" && go test -count=5 -v -tags e2etest ./internal/agent -run "^(TestNginxDeployProfiles|TestNginxStagedFaultRollsBack)$"'

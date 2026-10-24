#!/usr/bin/env bash
# ACME conformance run (PHASE2 step 14, owner Q5): real clients – lego,
# certbot (http-01, and dns-01 with certbot-dns-rfc2136 against BIND),
# acme.sh – against MyOwnPKI's ACME server, plus a control run of lego
# against Pebble. Needs Linux, Docker, Go and OpenSSL; CI runs it in its own
# job (task acme:conformance). Nothing of this reaches the release binary:
# the tools are built into .tools/, the images run only here.
#
# Two packages, one after the other (-p 1: both need port 80): internal/acme
# (the clients through a TLS stand-in for the reverse proxy) and
# internal/server (lego and certbot directly against the own TLS listener,
# acme.tls_issuer, v0.2.2).
#
# Pinning: lego and Pebble by version (Taskfile.yml), the images by digest.
# Each was at least two weeks old when pinned (tag dates on Docker Hub).
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
LEGO_VERSION=${LEGO_VERSION:?set by Taskfile.yml}
PEBBLE_VERSION=${PEBBLE_VERSION:?set by Taskfile.yml}
# Tag for the reader, digest for the pull. Dates: tag last pushed.
BIND_IMAGE="internetsystemsconsortium/bind9:9.18@sha256:1ffb29c718ee2540c5643c1e8166629a07bbd505f99107baae535e9f86eb7eef" # 2026-09-15
CERTBOT_IMAGE="certbot/dns-rfc2136:v5.8.0@sha256:55d52a5de51df312cadbcce1dc105f20d639bc127699e791323c2a27db05ac1f"        # 2026-09-01
ACMESH_IMAGE="neilpang/acme.sh:3.1.5@sha256:05a6a9e0276e148b3671c9f599bab098559a2d2a09e5811d44db9fe1da87d416"              # 2026-09-19
BIND_NAME=myownpki-conformance-bind
DNS_PORT=5300

work=${CONF_WORK:-$(mktemp -d)}
mkdir -p "$work/bind/conf" "$work/bind/zones"
host_ip=${CONF_HOST_IP:-$(hostname -I | awk '{print $1}')}
if [ -z "$host_ip" ]; then
  echo "no address of this host found – set CONF_HOST_IP" >&2
  exit 1
fi
echo "work directory: $work, clients answer on $host_ip:80"

# A fresh TSIG key per run: never in the repository, masked in the CI log.
tsig_secret=$(openssl rand -base64 32)
if [ -n "${GITHUB_ACTIONS:-}" ]; then
  echo "::add-mask::$tsig_secret"
fi
sed -e "s|@TSIG_SECRET@|$tsig_secret|" "$root/test/conformance/bind/named.conf.in" >"$work/bind/conf/named.conf"
sed -e "s|@HOST_IP@|$host_ip|g" "$root/test/conformance/bind/homelab.lan.zone.in" >"$work/bind/zones/homelab.lan.zone"
# named runs as the user "bind" in the container and writes its journal.
chmod -R a+rwX "$work/bind"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- BIND log"
    docker logs "$BIND_NAME" 2>&1 | tail -n 50 || true
  fi
  docker rm -f "$BIND_NAME" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

docker pull --quiet "$BIND_IMAGE"
docker pull --quiet "$CERTBOT_IMAGE"
docker pull --quiet "$ACMESH_IMAGE"
docker run -d --name "$BIND_NAME" --network host \
  -v "$work/bind/conf:/etc/bind" -v "$work/bind/zones:/var/lib/bind" \
  "$BIND_IMAGE" -g -c /etc/bind/named.conf >/dev/null # the entrypoint adds "-u bind"

# The clients listen on port 80 without root.
if [ "$(id -u)" -ne 0 ] && [ "$(sysctl -n net.ipv4.ip_unprivileged_port_start)" -gt 80 ]; then
  sudo sysctl -q -w net.ipv4.ip_unprivileged_port_start=80
fi

# Test tools at pinned versions, verified against the Go checksum database.
GOFLAGS='' CGO_ENABLED=0 GOBIN="$root/.tools" go install "github.com/go-acme/lego/v5@v$LEGO_VERSION"
GOFLAGS='' CGO_ENABLED=0 GOBIN="$root/.tools" go install "github.com/letsencrypt/pebble/v2/cmd/pebble@v$PEBBLE_VERSION"
pebble_dir=$(cd "$work" && GOFLAGS='' go mod download -json "github.com/letsencrypt/pebble/v2@v$PEBBLE_VERSION" |
  sed -n 's/.*"Dir": "\(.*\)".*/\1/p')

cd "$root"
CONF_WORK="$work" CONF_HOST_IP="$host_ip" CONF_DNS="127.0.0.1:$DNS_PORT" \
  CONF_TSIG_NAME=acme-conformance CONF_TSIG_SECRET="$tsig_secret" \
  CONF_CERTBOT_IMAGE="$CERTBOT_IMAGE" CONF_ACMESH_IMAGE="$ACMESH_IMAGE" \
  LEGO_BIN="$root/.tools/lego" PEBBLE_BIN="$root/.tools/pebble" PEBBLE_DIR="$pebble_dir" \
  CGO_ENABLED=0 go test -p 1 -tags conformance -run '^TestConformance' -count=1 -v -timeout 25m ./internal/acme/ ./internal/server/

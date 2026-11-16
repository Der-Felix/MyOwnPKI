#!/usr/bin/env bash
# The demo of deploy/demo end to end, on the image the snapshot step built
# (docs/PHASE3.md §17, step 76): the compose file resolves, the stack comes up
# sealed, demo.sh unseals it, creates the domain, certbot gets a certificate by
# http-01, the chain verifies against the demo root with `openssl verify`, the
# certificate has exactly the requested name and the audit log has the
# issuance; the web image of the second act builds; and `docker compose down
# -v` leaves no container, network or volume behind.
#
# The second act (agent enrollment and its approval) is a live test.
#
# Run after scripts/ci/image-snapshot.sh in the same job: it uses the image the
# snapshot left in the local image store. MYOWNPKI_IMAGE names another image.
#
# The demo secrets file never reaches this log: demo.sh masks every value of it
# (::add-mask::), never prints one, and the failure output below holds only the
# container logs, which carry no secrets (the file is read by `compose cp` and
# deleted).
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
compose_file=$root/deploy/demo/docker-compose.yml

fail() {
  printf '::error::%s\n' "$*"
  exit 1
}
step() { printf '\n=== %s\n' "$*"; }

for tool in docker curl openssl; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is needed"
done
docker compose version >/dev/null 2>&1 || fail "the docker compose plugin is needed"

# The image of the runner's own architecture from the snapshot (the images
# of the snapshot are local tags <version>-amd64 and <version>-arm64).
if [ -z "${MYOWNPKI_IMAGE:-}" ]; then
  case "$(uname -m)" in
    aarch64 | arm64) native=arm64 ;;
    *) native=amd64 ;;
  esac
  MYOWNPKI_IMAGE=$(docker image ls ghcr.io/der-felix/myownpki --format '{{.Repository}}:{{.Tag}}' | grep -- "-$native\$" | head -n 1) ||
    fail "no local snapshot image ghcr.io/der-felix/myownpki:*-$native - run scripts/ci/image-snapshot.sh first"
fi
export MYOWNPKI_IMAGE
echo "demo image: $MYOWNPKI_IMAGE"

dc() {
  docker compose --project-directory "$root/deploy/demo" -f "$compose_file" \
    --profile init --profile certbot --profile agent "$@"
}

cleanup() {
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ]; then
    echo '--- demo containers'
    dc ps -a 2>&1 || true
    echo '--- logs (server, certbot, web; no secrets in them)'
    dc logs --no-color --tail 80 myownpki certbot web 2>&1 || true
  fi
  # Whatever happened: the demo's containers, network and volumes go.
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  docker image rm -f myownpki-demo-web:local >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

step "1. The compose file resolves"
dc config --quiet || fail "docker compose config failed"
dc config --images | sort -u

step "2. The whole demo: up, unseal, domain, certbot, verify"
bash deploy/demo/demo.sh run

step "3. The image of the second act builds and carries the agent of this release"
dc build web
agent=$(docker run --rm --entrypoint /usr/local/bin/myownpki-agent myownpki-demo-web:local --version) ||
  fail "the agent of the web image does not run"
case "$agent" in
  myownpki-agent\ *) echo "web image: $agent" ;;
  *) fail "unexpected agent version output: $agent" ;;
esac

step "4. down -v removes everything"
bash deploy/demo/demo.sh down
left=$(docker ps -a --format '{{.Names}}' | grep '^myownpki-demo-' || true)
[ -z "$left" ] || fail "containers are left: $left"
left=$(docker volume ls --format '{{.Name}}' | grep '^myownpki-demo_' || true)
[ -z "$left" ] || fail "volumes are left: $left"
left=$(docker network ls --format '{{.Name}}' | grep '^myownpki-demo' || true)
[ -z "$left" ] || fail "networks are left: $left"

step "The demo works end to end"

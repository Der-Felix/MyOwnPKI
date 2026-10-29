#!/usr/bin/env bash
# The release image as release.yml builds it, without pushing or signing:
# a GoReleaser snapshot with dockers_v2, then the image is checked for the
# agent packages the server serves. CI snapshots elsewhere skip the image, so
# without this job an image problem shows only after the release tag.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"
# shellcheck source=scripts/ci/disposable.sh
source scripts/ci/disposable.sh
# It switches the Docker daemon to the containerd image store and restarts it.
ci_require_disposable

fail() {
  printf '::error::%s\n' "$*"
  exit 1
}

# Multi-platform images need the containerd image store (as in release.yml).
if [ -s /etc/docker/daemon.json ]; then cfg=$(sudo cat /etc/docker/daemon.json); else cfg='{}'; fi
echo "$cfg" | jq '.features["containerd-snapshotter"] = true' | sudo tee /etc/docker/daemon.json >/dev/null
sudo systemctl restart docker
docker info --format '{{json .DriverStatus}}' | grep -q 'io.containerd.snapshotter' ||
  fail "Docker did not switch to the containerd image store"

goreleaser release --snapshot --clean --skip=sign,sbom

image=$(docker image ls ghcr.io/der-felix/myownpki --format '{{.Repository}}:{{.Tag}}' | head -n 1)
[ -n "$image" ] || fail "the snapshot built no image ghcr.io/der-felix/myownpki"
echo "Checking $image"

env=$(docker image inspect --format '{{json .Config.Env}}' "$image")
grep -q '"MYOWNPKI_AGENT_PACKAGE_DIR=/opt/myownpki/agent-dist"' <<<"$env" ||
  fail "the image does not point agent.package_dir at /opt/myownpki/agent-dist: $env"

work=$RUNNER_TEMP/image-check
rm -rf "$work"
mkdir -p "$work"
cid=$(docker create --platform linux/amd64 "$image")
docker cp "$cid:/opt/myownpki/agent-dist" "$work/agent-dist"
docker rm "$cid" >/dev/null

cmp dist/checksums.txt "$work/agent-dist/checksums.txt" || fail "checksums.txt in the image differs from dist/"
count=0
for arch in amd64 arm64; do
  for ext in deb rpm tar.gz; do
    path=$(compgen -G "$work/agent-dist/myownpki-agent_*_linux_${arch}.${ext}") ||
      fail "the image has no agent package for $arch $ext"
    name=$(basename "$path")
    want=$(awk -v f="$name" '$2 == f { print $1 }' dist/checksums.txt)
    [ -n "$want" ] || fail "$name is not in dist/checksums.txt"
    [ "$(sha256sum "$path" | awk '{ print $1 }')" = "$want" ] || fail "$name in the image does not match checksums.txt"
    count=$((count + 1))
  done
done
echo "The image serves $count agent packages and checksums.txt from /opt/myownpki/agent-dist."

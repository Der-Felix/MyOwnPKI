#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"
# shellcheck source=scripts/ci/disposable.sh
source scripts/ci/disposable.sh
ci_require_disposable
ci_refuse_existing_agent

image=nginx:1.29.2-trixie@sha256:029d4461bd98f124e531380505ceea2072418fdf28752aa73b7b273ba3048903
rootfs=/var/lib/myownpki-agent-e2e/rootfs
container=$(docker create "$image")
cleanup_agent_e2e() {
  if [ -n "${container:-}" ]; then
    docker rm -f "$container" 2>/dev/null || true
  fi
  sudo systemctl stop myownpki-agent.service >/dev/null 2>&1 || true
  sudo rm -rf /etc/systemd/system/myownpki-agent.service.d \
    /etc/systemd/system/myownpki-agent.service /var/lib/myownpki-agent-e2e \
    /usr/local/bin/myownpki-agent
  sudo systemctl reset-failed myownpki-agent.service >/dev/null 2>&1 || true
  sudo systemctl daemon-reload
}
trap cleanup_agent_e2e EXIT
sudo rm -rf /var/lib/myownpki-agent-e2e
sudo install -d -m 0755 "$rootfs"
docker export "$container" | sudo tar -x -C "$rootfs"
docker rm "$container"
container=
bash scripts/ci/agent-e2e-test-binary.sh "$RUNNER_TEMP/myownpki-agent-e2e.test" ./internal/agent
sudo install -D -m 0755 "$RUNNER_TEMP/myownpki-agent-e2e.test" "$rootfs/usr/local/libexec/myownpki-agent-e2e.test"
sudo install -m 0644 deploy/systemd/myownpki-agent.service /etc/systemd/system/myownpki-agent.service
sudo install -d -m 0755 /etc/systemd/system/myownpki-agent.service.d
# systemd.exec(5): ReadWritePaths= is relative to the runner's root
# unless prefixed with '+'. It does not name a directory in this
# CI-only RootDirectory. Keep nginx's files in StateDirectory instead.
# A real host has no RootDirectory and uses 10-paths.conf normally.
printf '[Service]\nReadWritePaths=/var/lib/myownpki-agent\n' |
  sudo tee /etc/systemd/system/myownpki-agent.service.d/10-paths.conf >/dev/null
{
  printf '[Service]\n'
  printf 'Restart=no\n'
  printf 'RootDirectory=%s\n' "$rootfs"
  printf 'ExecStart=\n'
  printf 'ExecStart=/usr/local/libexec/myownpki-agent-e2e.test -test.run=^TestNginxPort443InSystemdSandbox$ -test.v\n'
  printf 'Environment=MYOWNPKI_SYSTEMD_E2E=1\n'
} | sudo tee /etc/systemd/system/myownpki-agent.service.d/99-ci.conf >/dev/null
sudo install -d -m 0700 "$rootfs/var/lib/myownpki-agent"
nginx_uid=$(awk -F: '$1 == "nginx" { print $3 }' "$rootfs/etc/passwd")
nginx_gid=$(awk -F: '$1 == "nginx" { print $4 }' "$rootfs/etc/passwd")
[ -n "$nginx_uid" ] && [ -n "$nginx_gid" ] || { echo '::error::nginx user missing in the pinned image'; exit 1; }
for directory in body fastcgi proxy scgi uwsgi; do
  sudo install -d -m 0755 -o "$nginx_uid" -g "$nginx_gid" "$rootfs/var/lib/nginx/$directory"
done
for directory in client_temp fastcgi_temp proxy_temp scgi_temp uwsgi_temp; do
  sudo install -d -m 0755 -o "$nginx_uid" -g "$nginx_gid" "$rootfs/var/cache/nginx/$directory"
done
sudo systemctl daemon-reload
# Negative control: without CAP_NET_BIND_SERVICE the same nginx test
# must fail and its sanitized stderr must explain the missing right.
sudo systemctl start myownpki-agent.service || true
for _ in $(seq 1 30); do
  sudo systemctl is-active --quiet myownpki-agent.service || break
  sleep 1
done
result=$(systemctl show --property Result --value myownpki-agent.service)
sudo journalctl -u myownpki-agent.service --no-pager -n 100 | tee "$RUNNER_TEMP/agent-no-low-ports.log" >/dev/null
if [ "$result" = success ] || ! grep -Fq 'bind() to 0.0.0.0:443 failed (13: Permission denied)' "$RUNNER_TEMP/agent-no-low-ports.log"; then
  echo '::error::the sandbox test did not detect the missing low-port capability'
  cat "$RUNNER_TEMP/agent-no-low-ports.log"
  exit 1
fi
# Positive control: the packaged drop-in fixes exactly this failure.
sudo install -m 0644 deploy/systemd/agent-low-ports.conf /etc/systemd/system/myownpki-agent.service.d/20-low-ports.conf
sudo systemctl daemon-reload
sudo systemctl reset-failed myownpki-agent.service
if ! sudo systemctl start myownpki-agent.service; then
  sudo journalctl -u myownpki-agent.service --no-pager -n 100
  exit 1
fi
for _ in $(seq 1 30); do
  sudo systemctl is-active --quiet myownpki-agent.service || break
  sleep 1
done
result=$(systemctl show --property Result --value myownpki-agent.service)
if [ "$result" != success ]; then
  sudo journalctl -u myownpki-agent.service --no-pager -n 100
  exit 1
fi
systemctl show --property Result --property ExecMainStatus myownpki-agent.service

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"
# shellcheck source=scripts/ci/disposable.sh
source scripts/ci/disposable.sh
ci_require_disposable
ci_refuse_existing_agent

package=$(compgen -G 'dist/myownpki-agent_*_linux_amd64.deb')
[ -f "$package" ]
name=$(basename "$package")
[[ $name =~ ^myownpki-agent_(.+)_linux_amd64\.deb$ ]]
version=${BASH_REMATCH[1]}
work=$RUNNER_TEMP/agent-package-systemd
control=$work/control
server_pid=
mkdir -p "$work"
cleanup() {
  if [ -n "$server_pid" ]; then
    sudo kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  sudo systemctl disable --now myownpki-agent.service >/dev/null 2>&1 || true
  sudo rm -rf /etc/systemd/system/myownpki-agent.service.d \
    /etc/systemd/system/myownpki-agent.service /etc/myownpki-agent \
    /usr/local/bin/myownpki-agent /var/lib/myownpki-agent
  if [ -f "$work/hosts.before" ]; then
    sudo cp "$work/hosts.before" /etc/hosts
  fi
  sudo systemctl daemon-reload
}
trap cleanup EXIT

CGO_ENABLED=0 go test -c -tags e2etest -o "$work/server.test" ./internal/server
CGO_ENABLED=0 go build -trimpath -o "$work/myownpki-agent-old" \
  -ldflags '-X github.com/Der-Felix/MyOwnPKI/internal/version.version=v0.3.1' ./cmd/myownpki-agent
sudo install -d -m 0700 "$control"
sudo install -d -m 0755 "$control/www"
sudo cp /etc/hosts "$work/hosts.before"
printf '127.0.0.1 pki.homelab.lan\n' | sudo tee -a /etc/hosts >/dev/null
sudo bash -c 'exec env MYOWNPKI_PACKAGE_E2E_DIST="$1" MYOWNPKI_PACKAGE_E2E_CONTROL="$2" MYOWNPKI_PACKAGE_E2E_VERSION="$3" "$4" -test.run "^TestAgentPackageDistributionE2E$" -test.v >"$5" 2>&1' \
  _ "$PWD/dist" "$control" "$version" "$work/server.test" "$work/server.log" &
server_pid=$!
ready=false
for _ in $(seq 1 1200); do
  if sudo test -f "$control/ready"; then
    ready=true
    break
  fi
  if ! sudo kill -0 "$server_pid" >/dev/null 2>&1; then
    sudo cat "$work/server.log" >&2
    exit 1
  fi
  sleep 0.1
done
if ! $ready; then
  sudo cat "$work/server.log" >&2
  exit 1
fi

root_url=$(sudo cat "$control/root-url")
root_sha256=$(sudo cat "$control/root-sha256")
package_name=$(sudo cat "$control/package-name")
package_sha256=$(sudo cat "$control/package-sha256")
sudo curl --fail --silent --show-error --output "$control/root.pem" "$root_url"
actual_root=$(sudo openssl x509 -in "$control/root.pem" -outform DER | sha256sum | awk '{print $1}')
[ "$actual_root" = "$root_sha256" ]
sudo curl --fail --silent --show-error --cacert "$control/root.pem" \
  --output "$control/$package_name" "https://pki.homelab.lan:8444/agent-packages/$package_name"
sudo curl --fail --silent --show-error --cacert "$control/root.pem" \
  --output "$control/checksums.txt" 'https://pki.homelab.lan:8444/agent-packages/checksums.txt'
printf '%s  %s\n' "$package_sha256" "$control/$package_name" | sudo sha256sum --check -

sudo dpkg -i "$control/$package_name" >/dev/null
if systemctl is-enabled --quiet myownpki-agent.service 2>/dev/null; then
  echo 'package enabled the agent' >&2
  exit 1
fi
if systemctl is-active --quiet myownpki-agent.service 2>/dev/null; then
  echo 'package started the agent' >&2
  exit 1
fi
[ ! -e /etc/systemd/system/myownpki-agent.service ]

sudo /usr/local/bin/myownpki-agent setup --server https://pki.homelab.lan:8444 \
  --ca-bundle "$control/root.pem" --root-sha256 "$root_sha256" --package-format deb \
  --hostname proxy1.homelab.lan --webroot "$control/www" --token-file "$control/join-token"
systemctl is-enabled --quiet myownpki-agent.service
systemctl is-active --quiet myownpki-agent.service
systemd-analyze verify /etc/systemd/system/myownpki-agent.service
sudo test ! -e "$control/join-token"
[ "$(stat -c %a /etc/myownpki-agent/root.pem)" = 600 ]
[ "$(stat -c %a /var/lib/myownpki-agent)" = 700 ]
before=$(sudo sha256sum /etc/myownpki-agent/agent.yaml | awk '{print $1}')

# Put an older agent on the enrolled host, then update it solely from the
# verified artifact served by the matching server.
sudo systemctl stop myownpki-agent.service
sudo install -m 0755 "$work/myownpki-agent-old" /usr/local/bin/myownpki-agent
sudo systemctl start myownpki-agent.service
sudo /usr/local/bin/myownpki-agent --version | grep -F 'myownpki-agent v0.3.1 '
sudo dpkg -i "$control/$package_name" >/dev/null
sudo /usr/local/bin/myownpki-agent setup --server https://pki.homelab.lan:8444 \
  --ca-bundle "$control/root.pem" --root-sha256 "$root_sha256" --package-format deb \
  --hostname proxy1.homelab.lan --webroot "$control/www"
systemctl is-active --quiet myownpki-agent.service
sudo /usr/local/bin/myownpki-agent --version | grep -F "myownpki-agent v$version "
[ "$(sudo sha256sum /etc/myownpki-agent/agent.yaml | awk '{print $1}')" = "$before" ]
sudo touch "$control/done"
if ! wait "$server_pid"; then
  sudo cat "$work/server.log" >&2
  exit 1
fi
server_pid=
sudo cat "$work/server.log"
printf 'Served package verification, enrollment and older-agent update passed on real systemd; package itself did not autostart.\n'

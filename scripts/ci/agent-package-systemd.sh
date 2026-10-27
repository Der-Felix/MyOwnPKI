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
work=$RUNNER_TEMP/agent-package-systemd
mkdir -p "$work"
cleanup() {
  sudo systemctl disable --now myownpki-agent.service >/dev/null 2>&1 || true
  sudo rm -rf /etc/systemd/system/myownpki-agent.service.d \
    /etc/systemd/system/myownpki-agent.service /etc/myownpki-agent \
    /usr/local/bin/myownpki-agent /var/lib/myownpki-agent
  sudo systemctl daemon-reload
}
trap cleanup EXIT

sudo dpkg -i "$package" >/dev/null
if systemctl is-enabled --quiet myownpki-agent.service 2>/dev/null; then
  echo 'package enabled the agent' >&2
  exit 1
fi
if systemctl is-active --quiet myownpki-agent.service 2>/dev/null; then
  echo 'package started the agent' >&2
  exit 1
fi
[ ! -e /etc/systemd/system/myownpki-agent.service ]

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj /CN=MyOwnPKI-setup-systemd-test -addext basicConstraints=critical,CA:TRUE \
  -keyout "$work/agent.key" -out "$work/root.pem" >/dev/null 2>&1
fingerprint=$(openssl x509 -in "$work/root.pem" -outform DER | sha256sum | awk '{print $1}')
sudo install -m 0600 "$work/root.pem" /etc/myownpki-agent/root.pem
sudo install -m 0600 "$work/root.pem" /var/lib/myownpki-agent/agent.crt
sudo install -m 0600 "$work/agent.key" /var/lib/myownpki-agent/agent.key
printf '{"id":"package-systemd-test"}\n' | sudo tee /var/lib/myownpki-agent/agent.json >/dev/null
sudo chmod 0600 /var/lib/myownpki-agent/agent.json
cat >"$work/agent.yaml" <<'EOF'
server: "https://pki.homelab.lan:8444"
ca_bundle: "/etc/myownpki-agent/root.pem"
hostname: "proxy1.homelab.lan"
state_dir: "/var/lib/myownpki-agent"
log_level: "info"
enrollment:
  challenge: standalone
paths: []
deployments: []
EOF
sudo install -m 0644 "$work/agent.yaml" /etc/myownpki-agent/agent.yaml
before=$(sha256sum /etc/myownpki-agent/agent.yaml | awk '{print $1}')
sudo /usr/local/bin/myownpki-agent setup --server https://pki.homelab.lan:8444 \
  --ca-bundle "$work/root.pem" --root-sha256 "$fingerprint"
systemctl is-enabled --quiet myownpki-agent.service
systemctl is-active --quiet myownpki-agent.service
systemd-analyze verify /etc/systemd/system/myownpki-agent.service
[ "$(stat -c %a /etc/myownpki-agent/root.pem)" = 600 ]
[ "$(stat -c %a /var/lib/myownpki-agent)" = 700 ]
after=$(sha256sum /etc/myownpki-agent/agent.yaml | awk '{print $1}')
[ "$before" = "$after" ]
sudo /usr/local/bin/myownpki-agent setup --server https://pki.homelab.lan:8444 \
  --ca-bundle "$work/root.pem" --root-sha256 "$fingerprint"
systemctl is-active --quiet myownpki-agent.service
[ "$(sha256sum /etc/myownpki-agent/agent.yaml | awk '{print $1}')" = "$before" ]
printf 'Real package setup and systemd already-enrolled/update path passed; package itself did not autostart.\n'

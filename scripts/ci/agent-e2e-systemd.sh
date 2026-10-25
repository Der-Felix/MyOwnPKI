#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"
: "${GITHUB_STEP_SUMMARY:?set GITHUB_STEP_SUMMARY}"
# shellcheck source=scripts/ci/disposable.sh
source scripts/ci/disposable.sh
ci_require_disposable
ci_refuse_existing_agent

go build -trimpath -o "$RUNNER_TEMP/myownpki-agent" ./cmd/myownpki-agent
cleanup_agent_systemd() {
  sudo rm -rf /etc/systemd/system/myownpki-agent.service.d \
    /etc/systemd/system/myownpki-agent.service /usr/local/bin/myownpki-agent
  sudo systemctl daemon-reload
}
trap cleanup_agent_systemd EXIT
sudo install -m 0755 "$RUNNER_TEMP/myownpki-agent" /usr/local/bin/myownpki-agent
sudo install -m 0644 deploy/systemd/myownpki-agent.service /etc/systemd/system/myownpki-agent.service
sudo systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/myownpki-agent.service
systemd-analyze security --no-pager myownpki-agent.service | tee "$RUNNER_TEMP/agent-security.txt"
exposure=$(sed -n 's/.*Overall exposure level for .*: \([0-9.]*\).*/\1/p' "$RUNNER_TEMP/agent-security.txt")
[ -n "$exposure" ] || { echo '::error::no overall exposure in systemd-analyze output'; exit 1; }
{
  printf '### systemd-analyze security myownpki-agent.service\n\nOverall exposure: **%s** (systemd %s)\n\n' \
    "$exposure" "$(systemctl --version | awk 'NR == 1 { print $2 }')"
  printf '<details><summary>All checks</summary>\n\n```text\n'
  cat "$RUNNER_TEMP/agent-security.txt"
  printf '```\n\n</details>\n'
} >>"$GITHUB_STEP_SUMMARY"

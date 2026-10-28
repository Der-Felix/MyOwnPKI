#!/usr/bin/env bash
# Shared guards for steps that replace system units, binaries or state.
# Source this file; it does not execute any checks by itself.

ci_require_disposable() {
  if [ "${GITHUB_ACTIONS:-}" != true ] && [ "${MYOWNPKI_CI_DISPOSABLE:-}" != 1 ]; then
    echo 'refusing to change /etc/systemd and /usr/local as root – only on a disposable runner (MYOWNPKI_CI_DISPOSABLE=1)' >&2
    return 1
  fi
}

ci_refuse_existing() {
  local path
  for path in "$@"; do
    if [ -e "$path" ] || [ -L "$path" ]; then
      echo "refusing to run: $path already exists and was not created by this script; nothing was changed or deleted" >&2
      return 1
    fi
  done
}

ci_refuse_existing_agent() {
  ci_refuse_existing \
    /etc/systemd/system/myownpki-agent.service \
    /etc/systemd/system/myownpki-agent.service.d \
    /usr/local/bin/myownpki-agent \
    /etc/myownpki-agent \
    /var/lib/myownpki-agent
}

ci_refuse_existing_server() {
  ci_refuse_existing \
    /etc/systemd/system/myownpki.service \
    /etc/systemd/system/myownpki.service.d \
    /etc/systemd/system/myownpki-backup.service \
    /etc/systemd/system/myownpki-backup.service.d \
    /etc/systemd/system/myownpki-backup.timer \
    /usr/local/bin/myownpki \
    /etc/myownpki \
    /var/lib/myownpki \
    /var/backups/myownpki
}

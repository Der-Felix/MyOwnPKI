#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD

# Central CI step registry: job | step | prerequisite | command.
# Keep this in .github/workflows/ci.yml job order. New steps belong here too.
steps=(
  'check|check|check_tools|bash scripts/ci/check-check.sh'
  'check|generate:check|generate_tools|bash scripts/ci/check-generate.sh'
  'check|agent protocol compatibility|go_git|bash scripts/ci/check-agent-protocol.sh'
  'check|fuzz ACME JWS parser|go_task|task fuzz'
  'check|upgrade from previous release|go_task|task upgrade:test'
  'race|tests with race detector|race_tools|bash scripts/ci/race-test.sh'
  'test-os|OpenSSL 3 from Homebrew|macos|bash scripts/ci/test-os-openssl.sh'
  'test-os|OpenSSL used by the tests|openssl|bash scripts/ci/test-os-openssl-version.sh'
  'test-os|go test|go|bash scripts/ci/test-os-test.sh'
  'test-os|Windows trust-page helper|windows|bash scripts/ci/test-os-windows-helper.sh'
  'cross|cross-compile release platforms|go_task|task cross'
  'vuln|govulncheck|go_task|task vuln'
  'lint-meta|actionlint|go_task|bash scripts/ci/lint-meta-actionlint.sh'
  'lint-meta|registry coverage|bash|bash scripts/ci/lint-meta-registry.sh --self-test'
  'lint-meta|vacuum OpenAPI|vacuum|task lint:api'
  'shellcheck|ShellCheck sources|shellcheck|bash scripts/ci/shellcheck-sources.sh'
  'shellcheck|legacy smoke test|linux|bash scripts/ci/shellcheck-smoke.sh'
  'conformance|lego walking skeleton EAB ARI|go_task|task acme:lego'
  'conformance|real-client conformance|linux_docker|CONF_WORK="$RUNNER_TEMP/conformance" task acme:conformance'
  'agent-e2e|download pinned Go modules|go|bash scripts/ci/agent-e2e-download.sh'
  'agent-e2e|cross-compile Linux agent test binary|go|GOOS=linux GOARCH=amd64 bash scripts/ci/agent-e2e-test-binary.sh .tools/ci/myownpki-agent-linux-amd64.test ./internal/agent'
  'agent-e2e|cross-compile Linux server test binary|go|GOOS=linux GOARCH=amd64 bash scripts/ci/agent-e2e-test-binary.sh .tools/ci/myownpki-server-linux-amd64.test ./internal/server'
  'agent-e2e|install-agent functions|bash_openssl|bash scripts/ci/agent-e2e-functions.sh'
  'agent-e2e|real server agent ACME nginx rollback|linux_docker|bash scripts/ci/agent-e2e-nginx.sh'
  'agent-e2e|systemd verify and security|linux_systemd_disposable|bash scripts/ci/agent-e2e-systemd.sh'
  'agent-e2e|nginx port 443 systemd controls|linux_systemd_docker_disposable|bash scripts/ci/agent-e2e-nginx-systemd.sh'
  'install|GoReleaser snapshot|linux_goreleaser|bash scripts/ci/install-snapshot.sh'
  'install|agent package formats and architectures|linux_docker_dpkg|bash scripts/ci/agent-package-inspect.sh'
  'install|agent packages in pinned distributions|linux_docker_openssl|bash scripts/ci/agent-package-distros.sh'
  'install|agent package real setup and systemd|linux_systemd_openssl_disposable|bash scripts/ci/agent-package-systemd.sh'
  'install|install.sh functions|linux_goreleaser|bash scripts/ci/install-functions.sh'
  'install|second build for update|linux|bash scripts/ci/install-second-build.sh'
  'install|install start update as root|linux_systemd_goreleaser_disposable|bash scripts/ci/install-systemd.sh'
  'image|release image snapshot with agent packages|linux_docker_goreleaser_disposable|bash scripts/ci/image-snapshot.sh'
)

only=
list=false
while [ "$#" -gt 0 ]; do
  case $1 in
    --only)
      [ "$#" -ge 2 ] || { echo '--only needs a job name' >&2; exit 2; }
      only=$2
      shift 2
      ;;
    --list)
      list=true
      shift
      ;;
    -h|--help)
      echo 'Usage: task ci:local [-- --list] or task ci:local [-- --only JOB]'
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

os_name() {
  case $(uname -s) in
    Linux*) echo linux ;;
    Darwin*) echo macos ;;
    MINGW*|MSYS*|CYGWIN*) echo windows ;;
    *) echo other ;;
  esac
}

has_commands() {
  local command_name
  for command_name in "$@"; do
    command -v "$command_name" >/dev/null 2>&1 || return 1
  done
}

disposable_allowed() {
  [ "${GITHUB_ACTIONS:-}" = true ] || [ "${MYOWNPKI_CI_DISPOSABLE:-}" = 1 ]
}

disposable_skip_reason() {
  echo 'changes /etc/systemd and /usr/local as root – only on a disposable runner (MYOWNPKI_CI_DISPOSABLE=1)'
}

requirement() {
  local os
  os=$(os_name)
  case $1 in
    check_tools)
      has_commands go task golangci-lint sqlc || echo 'needs Go + Task + pinned check tools (golangci-lint, sqlc)'
      ;;
    generate_tools)
      has_commands go task git tar || echo 'needs Go + Task + git + tar'
      ;;
    go) has_commands go || echo 'needs Go' ;;
    go_task) has_commands go task || echo 'needs Go + Task' ;;
    go_git) has_commands go git || echo 'needs Go + git' ;;
    race_tools)
      if [ "$os" != linux ] || ! has_commands go task free gcc; then
        echo 'needs Linux + CGO C compiler + free'
      fi
      ;;
    macos)
      if [ "$os" != macos ] || ! has_commands brew; then
        echo 'needs macOS + Homebrew'
      fi
      ;;
    windows) [ "$os" = windows ] || echo 'needs Windows' ;;
    openssl) has_commands openssl || echo 'needs openssl' ;;
    bash) has_commands bash || echo 'needs bash' ;;
    bash_openssl) has_commands bash openssl sha256sum || echo 'needs bash + openssl + sha256sum' ;;
    shellcheck) has_commands bash shellcheck || echo 'needs bash + shellcheck' ;;
    vacuum) has_commands go task vacuum || echo 'needs Go + Task + vacuum' ;;
    linux) [ "$os" = linux ] || echo 'needs Linux' ;;
    linux_docker)
      if [ "$os" != linux ] || ! has_commands go task docker; then
        echo 'needs Linux + docker'
      fi
      ;;
    linux_docker_dpkg)
      if [ "$os" != linux ] || ! has_commands docker dpkg-deb; then
        echo 'needs Linux + docker + dpkg-deb'
      fi
      ;;
    linux_docker_openssl)
      if [ "$os" != linux ] || ! has_commands docker openssl; then
        echo 'needs Linux + docker + openssl'
      fi
      ;;
    linux_systemd_openssl_disposable)
      if ! disposable_allowed; then
        disposable_skip_reason
      elif [ "$os" != linux ] || [ ! -d /run/systemd/system ] || ! has_commands sudo systemctl systemd-analyze openssl dpkg; then
        echo 'needs Linux + systemd + openssl + dpkg + sudo on a disposable runner'
      fi
      ;;
    linux_systemd_disposable)
      if ! disposable_allowed; then
        disposable_skip_reason
      elif [ "$os" != linux ] || [ ! -d /run/systemd/system ] || ! has_commands go sudo systemctl systemd-analyze; then
        echo 'needs Linux + systemd + sudo'
      fi
      ;;
    linux_systemd_docker_disposable)
      if ! disposable_allowed; then
        disposable_skip_reason
      elif [ "$os" != linux ] || [ ! -d /run/systemd/system ] || ! has_commands go sudo systemctl docker; then
        echo 'needs Linux + systemd + docker + sudo'
      fi
      ;;
    linux_goreleaser)
      if [ "$os" != linux ] || ! has_commands go bash goreleaser; then
        echo 'needs Linux + goreleaser'
      fi
      ;;
    linux_docker_goreleaser_disposable)
      if ! disposable_allowed; then
        disposable_skip_reason
      elif [ "$os" != linux ] || ! has_commands go sudo systemctl docker jq goreleaser; then
        echo 'needs Linux + docker + jq + goreleaser + sudo'
      fi
      ;;
    linux_systemd_goreleaser_disposable)
      if ! disposable_allowed; then
        disposable_skip_reason
      elif [ "$os" != linux ] || [ ! -d /run/systemd/system ] || ! has_commands go sudo systemctl goreleaser; then
        echo 'needs Linux + systemd + goreleaser + sudo'
      fi
      ;;
    *) echo "unknown prerequisite: $1" ;;
  esac
}

if $list; then
  printf '%-12s | %-44s | %-26s | %s\n' 'Job' 'Step' 'Prerequisite' 'Command'
  for entry in "${steps[@]}"; do
    IFS='|' read -r job step requires command <<<"$entry"
    if [ -z "$only" ] || [ "$job" = "$only" ]; then
      printf '%-12s | %-44s | %-26s | %s\n' "$job" "$step" "$requires" "$command"
    fi
  done
  exit 0
fi

if [ -n "${MYOWNPKI_CI_REMOTE_HOST:-}" ]; then
  printf 'MYOWNPKI_CI_REMOTE_HOST is reserved for a future owner-approved Linux runner; this run stays local.\n'
fi
export RUNNER_TEMP=${RUNNER_TEMP:-"$root/.tools/ci/runner-temp"}
export GITHUB_STEP_SUMMARY=${GITHUB_STEP_SUMMARY:-"$root/.tools/ci/step-summary.md"}
mkdir -p "$RUNNER_TEMP" "$(dirname "$GITHUB_STEP_SUMMARY")"

failed=0
matched=0
rows=()
for entry in "${steps[@]}"; do
  IFS='|' read -r job step requires command <<<"$entry"
  [ -z "$only" ] || [ "$job" = "$only" ] || continue
  matched=1
  if reason=$(requirement "$requires") && [ -z "$reason" ]; then
    printf '\n>>> %s / %s\n' "$job" "$step"
    started=$(date +%s)
    if bash -c "$command"; then
      status=PASS
    else
      status=FAIL
      failed=1
    fi
    duration="$(($(date +%s) - started))s"
    reason=
  else
    status=SKIP
    duration=0s
    [ -n "$reason" ] || reason="unmet prerequisite: $requires"
  fi
  rows+=("$(printf '%-12s | %-44s | %-4s | %-8s | %s' "$job" "$step" "$status" "$duration" "$reason")")
done

if [ "$matched" -eq 0 ]; then
  echo "unknown job: $only" >&2
  exit 2
fi
printf '\n%-12s | %-44s | %-4s | %-8s | %s\n' 'Job' 'Step' 'Status' 'Duration' 'Skip reason'
printf '%s\n' '-------------+----------------------------------------------+--------+----------+------------'
printf '%s\n' "${rows[@]}"
printf '\nLocal CI finished: %s\n' "$([ "$failed" -eq 0 ] && echo 'no failures' || echo 'FAILURES')"
exit "$failed"

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${RUNNER_TEMP:?set RUNNER_TEMP}"
# shellcheck source=scripts/ci/disposable.sh
source scripts/ci/disposable.sh
ci_require_disposable
ci_refuse_existing_server

archive=$(find dist -maxdepth 1 -name 'myownpki_*_linux_amd64.tar.gz')
sudo --preserve-env=GITHUB_ACTIONS,GITHUB_STEP_SUMMARY \
  bash test/install/systemd_test.sh "$archive" "$RUNNER_TEMP/update/myownpki"

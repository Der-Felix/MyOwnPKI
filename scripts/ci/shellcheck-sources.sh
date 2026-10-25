#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

bash legacy/build.sh
shellcheck --severity=warning --external-sources \
  legacy/*.sh legacy/tests/*.sh legacy/completions/*.bash \
  legacy/dist/pki-standalone.sh .github/scripts/*.sh scripts/ci/*.sh test/conformance/run.sh \
  deploy/install.sh deploy/install-agent.sh test/install/*.sh
shellcheck --severity=warning --exclude=SC2034 legacy/lib/*.sh

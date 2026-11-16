#!/usr/bin/env bash
# The apache2 recipe against the real Apache of Debian and Ubuntu (step 69).
# Needs the package apache2 (the CI job installs it); see the functions file.
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=scripts/ci/agent-e2e-services-functions.sh
source scripts/ci/agent-e2e-services-functions.sh

/usr/sbin/apache2 -v
e2e_services_run apache MYOWNPKI_E2E_APACHE '/usr/sbin/apache2 /usr/sbin/apache2ctl' \
  TestApacheDeployProfile TestApacheConfigtestOnKeyMismatch TestApacheStagedFaultRollsBack

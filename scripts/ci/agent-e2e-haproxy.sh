#!/usr/bin/env bash
# The haproxy recipe against the real HAProxy of Debian and Ubuntu (step 69).
# Needs the package haproxy (the CI job installs it); see the functions file.
set -euo pipefail
cd "$(dirname "$0")/../.."
# shellcheck source=scripts/ci/agent-e2e-services-functions.sh
source scripts/ci/agent-e2e-services-functions.sh

/usr/sbin/haproxy -v
e2e_services_run haproxy MYOWNPKI_E2E_HAPROXY /usr/sbin/haproxy \
  TestHAProxyDeployProfile TestHAProxyCheckOnKeyMismatch TestHAProxyDirectoryAndTemporaryFile \
  TestHAProxyCombinedOrder TestHAProxyStagedFaultRollsBack

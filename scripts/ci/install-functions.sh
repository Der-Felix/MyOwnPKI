#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

bash test/install/functions_test.sh dist/myownpki_linux_amd64_v1/myownpki

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

bash legacy/tests/smoke.sh

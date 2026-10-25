#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

bash test/install/agent_functions_test.sh

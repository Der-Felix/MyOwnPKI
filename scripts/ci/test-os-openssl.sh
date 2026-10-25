#!/usr/bin/env bash
set -euo pipefail

brew list openssl@3 >/dev/null 2>&1 || brew install openssl@3
echo "$(brew --prefix openssl@3)/bin" >>"$GITHUB_PATH"

#!/usr/bin/env bash
set -euo pipefail

sudo journalctl -u myownpki.service --no-pager -n 200

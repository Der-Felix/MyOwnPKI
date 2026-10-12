#!/usr/bin/env bash
###############################################################################
# gen-ca.sh - Abwaertskompatibler Aufruf fuer die modulare PKI Suite (pki.sh)
#
# Leitet alle Aufrufe transparent an pki.sh weiter.
###############################################################################
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

if [ -f "$SCRIPT_DIR/pki.sh" ]; then
    exec "$SCRIPT_DIR/pki.sh" "$@"
else
    echo "[FEHLER] pki.sh nicht gefunden in $SCRIPT_DIR" >&2
    exit 1
fi